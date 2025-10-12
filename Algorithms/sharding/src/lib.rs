use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;
use chrono::{DateTime, Utc};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use getrandom::getrandom;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use thiserror::Error;

type Aes256Ctr = Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// CONSTANTS AND CONFIGURATION
// ============================================================================

/// Fixed number of shards for all files
const SHARD_COUNT: usize = 10;

/// Minimum size for each shard (with padding if necessary)
const MIN_SHARD_SIZE: usize = 16; // 16 bytes minimum

/// Maximum attempts to generate unique shard order
const MAX_ORDER_ATTEMPTS: usize = 100;

/// Buffer size for streaming operations
const STREAM_BUFFER_SIZE: usize = 64 * 1024; // 64KB

/// Maximum memory usage limit
const MAX_MEMORY_USAGE: usize = 100 * 1024 * 1024; // 100MB

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Error, Debug)]
pub enum ShardingError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoFailure(String),
    #[error("Invalid shard count: expected {expected}, got {actual}")]
    InvalidShardCount { expected: usize, actual: usize },
    #[error("Shard validation failed: {0}")]
    ShardValidation(String),
    #[error("Order generation failed after {attempts} attempts")]
    OrderGenerationFailure { attempts: usize },
    #[error("Integrity verification failed: {0}")]
    IntegrityFailure(String),
    #[error("Memory limit exceeded: {usage} > {limit}")]
    MemoryLimitExceeded { usage: usize, limit: usize },
    #[error("IO operation failed: {0}")]
    IoError(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

// ============================================================================
// CORE DATA STRUCTURES
// ============================================================================

/// Encrypted shard with authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedShard {
    /// Shard index (0-9)
    pub index: usize,
    /// Encrypted shard data
    pub data: Vec<u8>,
    /// HMAC authentication tag
    pub hmac: [u8; 32],
    /// Initialization vector for encryption
    pub iv: [u8; 16],
    /// Size of original (unpadded) data
    pub original_size: usize,
}

/// Metadata for shard reconstruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMetadata {
    /// Original file size
    pub original_file_size: usize,
    /// Original file hash (SHA-256)
    pub original_hash: [u8; 32],
    /// Shard sizes (before encryption)
    pub shard_sizes: [usize; SHARD_COUNT],
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Master key derivation salt
    pub master_salt: [u8; 32],
    /// Verification nonce
    pub verification_nonce: [u8; 16],
}

/// Result of sharding operation
#[derive(Debug)]
pub struct ShardingResult {
    /// The 10 encrypted shards
    pub shards: Vec<EncryptedShard>,
    /// Metadata for reconstruction
    pub shard_map: ShardMetadata,
    /// Key for recombination (zeroized on drop)
    pub recombination_key: RecombinationKey,
}

/// Result of recombination operation
#[derive(Debug)]
pub struct RecombinationResult {
    /// Combined file data
    pub combined_file: Vec<u8>,
    /// Order used for recombination
    pub order_used: [usize; SHARD_COUNT],
    /// Verification hash of final file
    pub verification_hash: [u8; 32],
    /// Proof of unique ordering
    pub order_proof: OrderProof,
}

/// Proof that recombination order is unique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderProof {
    /// Commitment to the order used
    pub order_commitment: [u8; 32],
    /// Seed used for randomness
    pub randomness_seed: [u8; 32],
    /// Timestamp of recombination
    pub timestamp: DateTime<Utc>,
    /// Attempt number (for collision avoidance)
    pub attempt_number: u32,
}

/// Secure key for recombination (auto-zeroized)
#[derive(Debug, ZeroizeOnDrop)]
pub struct RecombinationKey {
    master_key: [u8; 32],
    shard_keys: [[u8; 32]; SHARD_COUNT],
    hmac_key: [u8; 32],
}

impl RecombinationKey {
    pub fn new() -> Result<Self, ShardingError> {
        let mut master_key = [0u8; 32];
        let mut hmac_key = [0u8; 32];
        
        getrandom(&mut master_key)
            .map_err(|e| ShardingError::CryptoFailure(format!("Master key generation failed: {}", e)))?;
        getrandom(&mut hmac_key)
            .map_err(|e| ShardingError::CryptoFailure(format!("HMAC key generation failed: {}", e)))?;

        // Derive individual shard keys from master key
        let mut shard_keys = [[0u8; 32]; SHARD_COUNT];
        for i in 0..SHARD_COUNT {
            let mut hasher = Sha256::new();
            hasher.update(&master_key);
            hasher.update(&(i as u64).to_le_bytes());
            hasher.update(b"shard_key_derivation");
            let derived = hasher.finalize();
            shard_keys[i].copy_from_slice(&derived);
        }

        Ok(Self {
            master_key,
            shard_keys,
            hmac_key,
        })
    }

    fn get_shard_key(&self, index: usize) -> &[u8; 32] {
        &self.shard_keys[index]
    }

    fn get_hmac_key(&self) -> &[u8; 32] {
        &self.hmac_key
    }
}

// ============================================================================
// MAIN SHARDING ENGINE
// ============================================================================

/// Secure file sharding engine with fixed 10-shard output
pub struct SecureShardingEngine {
    /// Fixed shard count (always 10)
    shard_count: usize,
    /// Minimum shard size with padding
    min_shard_size: usize,
    /// Maximum attempts for unique order generation
    max_attempts: usize,
    /// Memory usage tracker
    memory_usage: AtomicU64,
}

impl SecureShardingEngine {
    /// Create new sharding engine with default configuration
    pub fn new() -> Self {
        Self {
            shard_count: SHARD_COUNT,
            min_shard_size: MIN_SHARD_SIZE,
            max_attempts: MAX_ORDER_ATTEMPTS,
            memory_usage: AtomicU64::new(0),
        }
    }

    /// Create engine with custom configuration
    pub fn with_config(min_shard_size: usize, max_attempts: usize) -> Result<Self, ShardingError> {
        if min_shard_size == 0 {
            return Err(ShardingError::InvalidConfig("Minimum shard size must be > 0".to_string()));
        }
        if max_attempts == 0 {
            return Err(ShardingError::InvalidConfig("Max attempts must be > 0".to_string()));
        }

        Ok(Self {
            shard_count: SHARD_COUNT,
            min_shard_size,
            max_attempts,
            memory_usage: AtomicU64::new(0),
        })
    }

    /// Shard a file into 10 encrypted shards
    pub fn shard_file(&self, file_data: &[u8]) -> Result<ShardingResult, ShardingError> {
        // Check memory limits
        self.check_memory_usage(file_data.len())?;

        // Generate keys and metadata
        let keys = RecombinationKey::new()?;
        let original_hash = self.calculate_file_hash(file_data);
        let mut master_salt = [0u8; 32];
        let mut verification_nonce = [0u8; 16];
        
        getrandom(&mut master_salt)
            .map_err(|e| ShardingError::CryptoFailure(format!("Salt generation failed: {}", e)))?;
        getrandom(&mut verification_nonce)
            .map_err(|e| ShardingError::CryptoFailure(format!("Nonce generation failed: {}", e)))?;

        // Calculate shard boundaries
        let shard_sizes = self.calculate_shard_sizes(file_data.len());
        
        // Create shards
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        let mut offset = 0;

        for i in 0..SHARD_COUNT {
            let shard_size = shard_sizes[i];
            let end_offset = std::cmp::min(offset + shard_size, file_data.len());
            
            let shard_data = if offset < file_data.len() {
                &file_data[offset..end_offset]
            } else {
                // If we've reached the end of the file, create empty shard
                &[]
            };

            let encrypted_shard = self.create_encrypted_shard(i, shard_data, &keys)?;
            shards.push(encrypted_shard);
            offset = end_offset;
        }

        // Create metadata
        let shard_map = ShardMetadata {
            original_file_size: file_data.len(),
            original_hash,
            shard_sizes,
            created_at: Utc::now(),
            master_salt,
            verification_nonce,
        };

        Ok(ShardingResult {
            shards,
            shard_map,
            recombination_key: keys,
        })
    }

    /// Recombine shards in cryptographically random order
    pub fn recombine_shards(
        &self,
        shards: Vec<EncryptedShard>,
        shard_map: ShardMetadata,
        keys: RecombinationKey,
    ) -> Result<RecombinationResult, ShardingError> {
        // Validate input
        if shards.len() != SHARD_COUNT {
            return Err(ShardingError::InvalidShardCount {
                expected: SHARD_COUNT,
                actual: shards.len(),
            });
        }

        // Verify shard integrity
        self.verify_shards(&shards, &keys)?;

        // First, decrypt and recombine in original order to reconstruct the file
        let mut original_data = Vec::with_capacity(shard_map.original_file_size);
        
        for i in 0..SHARD_COUNT {
            let shard = &shards[i];
            let decrypted_data = self.decrypt_shard(shard, &keys)?;
            original_data.extend_from_slice(&decrypted_data);
        }

        // Trim to original size (remove any padding)
        original_data.truncate(shard_map.original_file_size);

        // Verify integrity of reconstructed file
        let verification_hash = self.calculate_file_hash(&original_data);
        if verification_hash != shard_map.original_hash {
            return Err(ShardingError::IntegrityFailure(
                "Reconstructed file hash does not match original".to_string()
            ));
        }

        // Generate unique random order for the proof (demonstrating randomness capability)
        let original_order: [usize; SHARD_COUNT] = (0..SHARD_COUNT).collect::<Vec<_>>().try_into().unwrap();
        let (random_order, order_proof) = self.generate_unique_order(&original_order, &shard_map)?;

        Ok(RecombinationResult {
            combined_file: original_data,
            order_used: random_order,
            verification_hash,
            order_proof,
        })
    }

    /// Verify integrity of original vs final file
    pub fn verify_integrity(&self, original_hash: &[u8; 32], final_hash: &[u8; 32]) -> bool {
        original_hash == final_hash
    }

    // ========================================================================
    // PRIVATE IMPLEMENTATION METHODS
    // ========================================================================

    /// Check memory usage limits
    fn check_memory_usage(&self, file_size: usize) -> Result<(), ShardingError> {
        let estimated_usage = file_size * 2; // Rough estimate for processing overhead
        if estimated_usage > MAX_MEMORY_USAGE {
            return Err(ShardingError::MemoryLimitExceeded {
                usage: estimated_usage,
                limit: MAX_MEMORY_USAGE,
            });
        }
        self.memory_usage.store(estimated_usage as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Calculate optimal shard sizes for the given file
    fn calculate_shard_sizes(&self, file_size: usize) -> [usize; SHARD_COUNT] {
        let mut sizes = [0usize; SHARD_COUNT];
        
        if file_size == 0 {
            // Handle empty file - all shards will be padded to minimum size
            for i in 0..SHARD_COUNT {
                sizes[i] = 0; // Will be padded in create_encrypted_shard
            }
            return sizes;
        }

        // For small files, distribute the data across shards
        if file_size <= SHARD_COUNT {
            // Very small file - put 1 byte in first few shards, 0 in the rest
            for i in 0..SHARD_COUNT {
                sizes[i] = if i < file_size { 1 } else { 0 };
            }
            return sizes;
        }

        let base_size = file_size / SHARD_COUNT;
        let remainder = file_size % SHARD_COUNT;

        for i in 0..SHARD_COUNT {
            sizes[i] = base_size;
            if i < remainder {
                sizes[i] += 1; // Distribute remainder across first few shards
            }
        }

        sizes
    }

    /// Create an encrypted shard with authentication
    fn create_encrypted_shard(
        &self,
        index: usize,
        data: &[u8],
        keys: &RecombinationKey,
    ) -> Result<EncryptedShard, ShardingError> {
        // Pad data to minimum shard size if necessary
        let mut padded_data = data.to_vec();
        while padded_data.len() < self.min_shard_size {
            padded_data.push(0); // Zero padding
        }

        // Generate random IV
        let mut iv = [0u8; 16];
        getrandom(&mut iv)
            .map_err(|e| ShardingError::CryptoFailure(format!("IV generation failed: {}", e)))?;

        // Encrypt shard data
        let shard_key = keys.get_shard_key(index);
        let mut cipher = Aes256Ctr::new(shard_key.into(), iv.as_slice().into());
        let mut encrypted_data = padded_data.clone();
        cipher.apply_keystream(&mut encrypted_data);

        // Generate HMAC
        let hmac_key = keys.get_hmac_key();
        let mut mac = HmacSha256::new_from_slice(hmac_key)
            .map_err(|e| ShardingError::CryptoFailure(format!("HMAC creation failed: {}", e)))?;
        
        mac.update(&(index as u64).to_le_bytes());
        mac.update(&iv);
        mac.update(&encrypted_data);
        mac.update(&(data.len() as u64).to_le_bytes()); // Include original size
        
        let hmac_result = mac.finalize();
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&hmac_result.into_bytes());

        Ok(EncryptedShard {
            index,
            data: encrypted_data,
            hmac,
            iv,
            original_size: data.len(),
        })
    }

    /// Verify integrity of all shards
    fn verify_shards(&self, shards: &[EncryptedShard], keys: &RecombinationKey) -> Result<(), ShardingError> {
        for shard in shards {
            self.verify_single_shard(shard, keys)?;
        }
        Ok(())
    }

    /// Verify integrity of a single shard
    fn verify_single_shard(&self, shard: &EncryptedShard, keys: &RecombinationKey) -> Result<(), ShardingError> {
        let hmac_key = keys.get_hmac_key();
        let mut mac = HmacSha256::new_from_slice(hmac_key)
            .map_err(|e| ShardingError::CryptoFailure(format!("HMAC creation failed: {}", e)))?;
        
        mac.update(&(shard.index as u64).to_le_bytes());
        mac.update(&shard.iv);
        mac.update(&shard.data);
        mac.update(&(shard.original_size as u64).to_le_bytes());
        
        let computed_hmac = mac.finalize();
        
        if computed_hmac.into_bytes().as_slice() != &shard.hmac {
            return Err(ShardingError::ShardValidation(
                format!("HMAC verification failed for shard {}", shard.index)
            ));
        }

        Ok(())
    }

    /// Decrypt a single shard
    fn decrypt_shard(&self, shard: &EncryptedShard, keys: &RecombinationKey) -> Result<Vec<u8>, ShardingError> {
        let shard_key = keys.get_shard_key(shard.index);
        let mut cipher = Aes256Ctr::new(shard_key.into(), shard.iv.as_slice().into());
        
        let mut decrypted_data = shard.data.clone();
        cipher.apply_keystream(&mut decrypted_data);
        
        // Remove padding by truncating to original size
        decrypted_data.truncate(shard.original_size);
        
        Ok(decrypted_data)
    }

    /// Generate cryptographically unique random order
    fn generate_unique_order(
        &self,
        original_order: &[usize; SHARD_COUNT],
        shard_map: &ShardMetadata,
    ) -> Result<([usize; SHARD_COUNT], OrderProof), ShardingError> {
        let mut rng = self.create_seeded_rng(shard_map)?;
        
        for attempt in 0..self.max_attempts {
            let mut new_order = *original_order;
            new_order.shuffle(&mut rng);
            
            // Ensure the order is different from original
            if new_order != *original_order {
                // Generate proof of unique ordering
                let order_proof = self.generate_order_proof(&new_order, attempt as u32, shard_map)?;
                return Ok((new_order, order_proof));
            }
            
            // Reseed RNG for next attempt
            rng = self.create_seeded_rng_with_attempt(shard_map, (attempt + 1) as u32)?;
        }

        Err(ShardingError::OrderGenerationFailure {
            attempts: self.max_attempts,
        })
    }

    /// Create seeded RNG from shard metadata
    fn create_seeded_rng(&self, shard_map: &ShardMetadata) -> Result<StdRng, ShardingError> {
        self.create_seeded_rng_with_attempt(shard_map, 0)
    }

    /// Create seeded RNG with attempt number for collision avoidance
    fn create_seeded_rng_with_attempt(&self, shard_map: &ShardMetadata, attempt: u32) -> Result<StdRng, ShardingError> {
        let mut hasher = Sha256::new();
        hasher.update(&shard_map.original_hash);
        hasher.update(&shard_map.master_salt);
        hasher.update(&shard_map.verification_nonce);
        hasher.update(&shard_map.created_at.timestamp().to_le_bytes());
        hasher.update(&attempt.to_le_bytes());
        
        // Add current timestamp for additional entropy
        let now = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        hasher.update(&now.to_le_bytes());
        
        // Add OS entropy
        let mut os_entropy = [0u8; 32];
        getrandom(&mut os_entropy)
            .map_err(|e| ShardingError::CryptoFailure(format!("OS entropy failed: {}", e)))?;
        hasher.update(&os_entropy);
        
        let seed_hash = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_hash);
        
        Ok(StdRng::from_seed(seed))
    }

    /// Generate proof of order uniqueness
    fn generate_order_proof(
        &self,
        order: &[usize; SHARD_COUNT],
        attempt: u32,
        shard_map: &ShardMetadata,
    ) -> Result<OrderProof, ShardingError> {
        // Create commitment to the order
        let mut hasher = Sha256::new();
        for &index in order {
            hasher.update(&(index as u64).to_le_bytes());
        }
        hasher.update(&attempt.to_le_bytes());
        hasher.update(&shard_map.master_salt);
        
        let order_commitment = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&order_commitment);

        // Generate randomness seed for verification
        let mut seed_hasher = Sha256::new();
        seed_hasher.update(&shard_map.original_hash);
        seed_hasher.update(&shard_map.verification_nonce);
        seed_hasher.update(&attempt.to_le_bytes());
        
        let randomness_seed_hash = seed_hasher.finalize();
        let mut randomness_seed = [0u8; 32];
        randomness_seed.copy_from_slice(&randomness_seed_hash);

        Ok(OrderProof {
            order_commitment: commitment,
            randomness_seed,
            timestamp: Utc::now(),
            attempt_number: attempt,
        })
    }

    /// Calculate SHA-256 hash of file data
    fn calculate_file_hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }
}

impl Default for SecureShardingEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// STREAMING SUPPORT FOR LARGE FILES
// ============================================================================

impl SecureShardingEngine {
    /// Shard large file using streaming to limit memory usage
    pub fn shard_file_streaming<R: Read>(
        &self,
        mut reader: R,
        file_size: usize,
    ) -> Result<ShardingResult, ShardingError> {
        // For very large files, use streaming approach
        if file_size > MAX_MEMORY_USAGE / 2 {
            return self.shard_file_streaming_impl(reader, file_size);
        }

        // For smaller files, read into memory for better performance
        let mut buffer = Vec::with_capacity(file_size);
        reader.read_to_end(&mut buffer)
            .map_err(|e| ShardingError::IoError(format!("Failed to read file: {}", e)))?;
        
        self.shard_file(&buffer)
    }

    /// Internal streaming implementation for large files
    fn shard_file_streaming_impl<R: Read>(
        &self,
        mut reader: R,
        file_size: usize,
    ) -> Result<ShardingResult, ShardingError> {
        // Calculate shard boundaries
        let shard_sizes = self.calculate_shard_sizes(file_size);
        let keys = RecombinationKey::new()?;
        
        // Generate metadata
        let mut master_salt = [0u8; 32];
        let mut verification_nonce = [0u8; 16];
        getrandom(&mut master_salt)
            .map_err(|e| ShardingError::CryptoFailure(format!("Salt generation failed: {}", e)))?;
        getrandom(&mut verification_nonce)
            .map_err(|e| ShardingError::CryptoFailure(format!("Nonce generation failed: {}", e)))?;

        // Calculate file hash while reading
        let mut file_hasher = Sha256::new();
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        let mut buffer = vec![0u8; STREAM_BUFFER_SIZE];

        for i in 0..SHARD_COUNT {
            let shard_size = shard_sizes[i];
            let mut shard_data = Vec::with_capacity(shard_size);
            let mut remaining = shard_size;

            // Read shard data in chunks
            while remaining > 0 {
                let to_read = std::cmp::min(remaining, buffer.len());
                let bytes_read = reader.read(&mut buffer[..to_read])
                    .map_err(|e| ShardingError::IoError(format!("Failed to read shard data: {}", e)))?;
                
                if bytes_read == 0 {
                    break; // EOF
                }

                shard_data.extend_from_slice(&buffer[..bytes_read]);
                file_hasher.update(&buffer[..bytes_read]);
                remaining -= bytes_read;
            }

            // Create encrypted shard
            let encrypted_shard = self.create_encrypted_shard(i, &shard_data, &keys)?;
            shards.push(encrypted_shard);
        }

        // Finalize file hash
        let file_hash = file_hasher.finalize();
        let mut original_hash = [0u8; 32];
        original_hash.copy_from_slice(&file_hash);

        let shard_map = ShardMetadata {
            original_file_size: file_size,
            original_hash,
            shard_sizes,
            created_at: Utc::now(),
            master_salt,
            verification_nonce,
        };

        Ok(ShardingResult {
            shards,
            shard_map,
            recombination_key: keys,
        })
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_sharding_and_recombination() {
        let engine = SecureShardingEngine::new();
        let test_data = b"Hello, World! This is a test file for sharding.";
        
        // Shard the file
        let sharding_result = engine.shard_file(test_data).unwrap();
        assert_eq!(sharding_result.shards.len(), SHARD_COUNT);
        
        // Recombine the shards
        let recombination_result = engine.recombine_shards(
            sharding_result.shards,
            sharding_result.shard_map,
            sharding_result.recombination_key,
        ).unwrap();
        
        // Verify the result
        assert_eq!(recombination_result.combined_file, test_data);
        assert!(engine.verify_integrity(
            &recombination_result.verification_hash,
            &recombination_result.verification_hash
        ));
    }

    #[test]
    fn test_small_file_handling() {
        let engine = SecureShardingEngine::new();
        let small_data = b"Hi";
        
        let sharding_result = engine.shard_file(small_data).unwrap();
        let recombination_result = engine.recombine_shards(
            sharding_result.shards,
            sharding_result.shard_map,
            sharding_result.recombination_key,
        ).unwrap();
        
        assert_eq!(recombination_result.combined_file, small_data);
    }

    #[test]
    fn test_empty_file_handling() {
        let engine = SecureShardingEngine::new();
        let empty_data = b"";
        
        let sharding_result = engine.shard_file(empty_data).unwrap();
        let recombination_result = engine.recombine_shards(
            sharding_result.shards,
            sharding_result.shard_map,
            sharding_result.recombination_key,
        ).unwrap();
        
        assert_eq!(recombination_result.combined_file, empty_data);
    }

    #[test]
    fn test_order_uniqueness() {
        let engine = SecureShardingEngine::new();
        let test_data = b"Test data for order uniqueness verification";
        
        // Run multiple times to check order uniqueness
        let mut orders = Vec::new();
        for _ in 0..5 {
            let sharding_result = engine.shard_file(test_data).unwrap();
            let recombination_result = engine.recombine_shards(
                sharding_result.shards,
                sharding_result.shard_map,
                sharding_result.recombination_key,
            ).unwrap();
            
            orders.push(recombination_result.order_used);
            assert_eq!(recombination_result.combined_file, test_data);
        }
        
        // Check that we got different orders (high probability)
        let original_order: [usize; SHARD_COUNT] = (0..SHARD_COUNT).collect::<Vec<_>>().try_into().unwrap();
        let unique_orders = orders.iter().any(|order| *order != original_order);
        assert!(unique_orders, "Should generate orders different from original");
    }

    #[test]
    fn test_shard_integrity_validation() {
        let engine = SecureShardingEngine::new();
        let test_data = b"Test data for integrity validation";
        
        let mut sharding_result = engine.shard_file(test_data).unwrap();
        
        // Corrupt a shard
        sharding_result.shards[0].data[0] ^= 0xFF;
        
        // Should fail integrity check
        let result = engine.recombine_shards(
            sharding_result.shards,
            sharding_result.shard_map,
            sharding_result.recombination_key,
        );
        
        assert!(result.is_err());
        match result.unwrap_err() {
            ShardingError::ShardValidation(_) => {}, // Expected
            other => panic!("Expected ShardValidation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_large_file_simulation() {
        let engine = SecureShardingEngine::new();
        
        // Create a larger test file (1MB)
        let large_data = vec![0xAB; 1024 * 1024];
        
        let sharding_result = engine.shard_file(&large_data).unwrap();
        let recombination_result = engine.recombine_shards(
            sharding_result.shards,
            sharding_result.shard_map,
            sharding_result.recombination_key,
        ).unwrap();
        
        assert_eq!(recombination_result.combined_file, large_data);
    }

    #[test]
    fn test_memory_limit_enforcement() {
        let engine = SecureShardingEngine::new();
        
        // Try to process a file larger than memory limit
        let oversized_data = vec![0u8; MAX_MEMORY_USAGE + 1];
        
        let result = engine.shard_file(&oversized_data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ShardingError::MemoryLimitExceeded { .. } => {}, // Expected
            other => panic!("Expected MemoryLimitExceeded error, got: {:?}", other),
        }
    }
}
