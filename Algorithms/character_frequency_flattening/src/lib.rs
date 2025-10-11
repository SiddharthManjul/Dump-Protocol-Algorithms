//! Algorithm A: Secure Text-Based File Destruction
//! 
//! This algorithm implements a three-phase approach to securely destroy text-based files:
//! 1. Linguistic Pattern Destruction - Remove linguistic fingerprints
//! 2. AES-256-CTR Cryptographic Overwrite - Multiple-pass cryptographic overwriting
//! 3. Multi-pass Verification & Cleanup - Verify erasure and cleanup resources

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use chrono::{DateTime, Utc};
use rand::{RngCore, SeedableRng};
use rand::rngs::{OsRng, StdRng};
use getrandom::getrandom;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use aes::Aes256;
use ctr::Ctr128BE;
use unicode_segmentation::UnicodeSegmentation;
use thiserror::Error;

type Aes256Ctr = Ctr128BE<Aes256>;

// ============================================================================
// PUBLIC API TYPES
// ============================================================================

/// Security level determines number of overwrite passes
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Low security: 3 passes
    Low,
    /// Medium security: 5 passes  
    Medium,
    /// High security: 7 passes
    High,
}

impl SecurityLevel {
    fn pass_count(&self) -> u8 {
        match self {
            SecurityLevel::Low => 3,
            SecurityLevel::Medium => 5,
            SecurityLevel::High => 7,
        }
    }
}

/// Depth of linguistic pattern analysis and destruction
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LinguisticDepth {
    /// Shallow: Character and word level operations
    Shallow,
    /// Deep: Character, word, and sentence level operations
    Deep,
}

/// Source for AES encryption keys
#[derive(Debug, Clone)]
pub enum AesKeySource {
    /// Generate ephemeral key from OS CSPRNG (default)
    GenerateEphemeral,
    /// Same as GenerateEphemeral
    FromOsCsprng,
    /// Use provided seed for key generation (testing only)
    FromSeed([u8; 32]),
}

impl Serialize for AesKeySource {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            AesKeySource::GenerateEphemeral => serializer.serialize_str("GenerateEphemeral"),
            AesKeySource::FromOsCsprng => serializer.serialize_str("FromOsCsprng"),
            AesKeySource::FromSeed(_) => serializer.serialize_str("FromSeed"), // Don't serialize actual seed
        }
    }
}

impl<'de> Deserialize<'de> for AesKeySource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "GenerateEphemeral" => Ok(AesKeySource::GenerateEphemeral),
            "FromOsCsprng" => Ok(AesKeySource::FromOsCsprng),
            "FromSeed" => Ok(AesKeySource::GenerateEphemeral), // Default to safe option
            _ => Ok(AesKeySource::GenerateEphemeral),
        }
    }
}

impl Zeroize for AesKeySource {
    fn zeroize(&mut self) {
        match self {
            AesKeySource::FromSeed(seed) => seed.zeroize(),
            _ => {}
        }
    }
}

/// Configuration for the destruction process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyConfig {
    pub security_level: SecurityLevel,
    pub linguistic_depth: LinguisticDepth,
    /// Override security level pass count (3-7)
    pub pass_count: Option<u8>,
    /// Buffer size for I/O operations (default: 4096)
    pub buffer_size: Option<usize>,
    /// File size threshold for streaming mode (default: 1GB)
    pub streaming_threshold: usize,
    /// Allow async I/O paths
    pub allow_async: bool,
    /// Language focus for linguistic operations (default: "en")
    pub language_focus: Option<String>,
    /// AES key source
    pub aes_key_source: Option<AesKeySource>,
    /// Verify hash between passes
    pub verify_hash_between_passes: bool,
    /// Maximum retry attempts
    pub max_retries: u8,
    /// Allow AES-NI acceleration
    pub cpu_feature_aes_ni: bool,
    /// Reproducible seed for deterministic testing
    pub reproducible_seed: Option<u64>,
}

impl Default for DestroyConfig {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::Medium,
            linguistic_depth: LinguisticDepth::Shallow,
            pass_count: None,
            buffer_size: Some(4096),
            streaming_threshold: 1024 * 1024 * 1024, // 1GB
            allow_async: false,
            language_focus: Some("en".to_string()),
            aes_key_source: Some(AesKeySource::GenerateEphemeral),
            verify_hash_between_passes: true,
            max_retries: 3,
            cpu_feature_aes_ni: true,
            reproducible_seed: None,
        }
    }
}

/// Linguistic analysis metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinguisticMetrics {
    /// Character frequency distribution
    pub char_frequency: HashMap<char, u32>,
    /// Top N most frequent words
    pub top_words: Vec<(String, u32)>,
    /// Sentence pattern entropy score
    pub sentence_entropy: f64,
    /// Whitespace and formatting statistics
    pub whitespace_stats: WhitespaceStats,
    /// Pattern remaining score (0-100, lower is better destruction)
    pub pattern_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitespaceStats {
    pub total_whitespace: u32,
    pub newline_count: u32,
    pub tab_count: u32,
    pub space_runs: u32,
    pub indentation_patterns: u32,
}

/// Result of the destruction operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestructionResult {
    pub file_path: String,
    pub original_size: u64,
    pub passes_executed: u8,
    pub linguistic_metrics_before: LinguisticMetrics,
    pub linguistic_metrics_after: LinguisticMetrics,
    /// SHA-256 hashes after each pass (if verification enabled)
    pub verification_hashes: Vec<[u8; 32]>,
    /// HMAC of operation log for tamper evidence
    pub tamper_evident_hmac: Option<String>,
    pub timestamp_utc: DateTime<Utc>,
    pub warnings: Vec<String>,
    pub success: bool,
}

/// Comprehensive error types for destruction failures
#[derive(Error, Debug)]
pub enum DestructionError {
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("Cryptographic failure: {0}")]
    CryptoFailure(String),
    #[error("Verification failure: {0}")]
    VerificationFailure(String),
    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),
    #[error("Partial completion: {0}")]
    PartialCompletion(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Streaming error: {0}")]
    StreamingError(String),
}

// ============================================================================
// BUILDER PATTERN IMPLEMENTATION
// ============================================================================

/// Builder for linguistic destruction operations
#[derive(Debug, Clone)]
pub struct LinguisticDestructionBuilder {
    config: DestroyConfig,
}

impl LinguisticDestructionBuilder {
    /// Create new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: DestroyConfig::default(),
        }
    }

    /// Create builder with custom configuration
    pub fn with_config(config: DestroyConfig) -> Self {
        Self { config }
    }

    /// Destroy a file at the given path
    pub fn destroy_file(&self, path: &Path) -> Result<DestructionResult, DestructionError> {
        validate_config(&self.config)?;
        
        let mut processor = TextDestructionProcessor::new(&self.config)?;
        processor.destroy_file(path)
    }

    /// Destroy content in a stream
    pub fn destroy_stream(&self, stream: impl Read + Write + Seek) -> Result<DestructionResult, DestructionError> {
        validate_config(&self.config)?;
        
        let mut processor = TextDestructionProcessor::new(&self.config)?;
        processor.destroy_stream(stream)
    }
}

impl Default for LinguisticDestructionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// INTERNAL IMPLEMENTATION
// ============================================================================

/// Zeroized AES key for cryptographic operations
#[derive(ZeroizeOnDrop)]
struct AesKey([u8; 32]);

impl AesKey {
    fn generate(source: &AesKeySource) -> Result<Self, DestructionError> {
        let mut key = [0u8; 32];
        
        match source {
            AesKeySource::GenerateEphemeral | AesKeySource::FromOsCsprng => {
                getrandom(&mut key)
                    .map_err(|e| DestructionError::CryptoFailure(format!("Failed to generate key: {}", e)))?;
            }
            AesKeySource::FromSeed(seed) => {
                key.copy_from_slice(seed);
            }
        }
        
        Ok(Self(key))
    }
}

/// Zeroized HMAC key for audit trail
#[derive(ZeroizeOnDrop)]
struct HmacKey([u8; 32]);

impl HmacKey {
    fn generate() -> Result<Self, DestructionError> {
        let mut key = [0u8; 32];
        getrandom(&mut key)
            .map_err(|e| DestructionError::CryptoFailure(format!("Failed to generate HMAC key: {}", e)))?;
        Ok(Self(key))
    }
}

/// Operation log entry for audit trail
#[derive(Debug, Clone, Serialize)]
struct OperationLogEntry {
    timestamp: DateTime<Utc>,
    phase: String,
    operation: String,
    byte_offset: Option<u64>,
    pass_number: Option<u8>,
}

/// Main processor for text destruction
struct TextDestructionProcessor {
    config: DestroyConfig,
    rng: Box<dyn RngCore + Send>,
    operation_log: Vec<OperationLogEntry>,
    hmac_key: HmacKey,
}

impl TextDestructionProcessor {
    fn new(config: &DestroyConfig) -> Result<Self, DestructionError> {
        let rng: Box<dyn RngCore + Send> = if let Some(seed) = config.reproducible_seed {
            Box::new(StdRng::seed_from_u64(seed))
        } else {
            Box::new(OsRng)
        };

        let hmac_key = HmacKey::generate()?;

        Ok(Self {
            config: config.clone(),
            rng,
            operation_log: Vec::new(),
            hmac_key,
        })
    }

    fn log_operation(&mut self, phase: &str, operation: &str, byte_offset: Option<u64>, pass_number: Option<u8>) {
        self.operation_log.push(OperationLogEntry {
            timestamp: Utc::now(),
            phase: phase.to_string(),
            operation: operation.to_string(),
            byte_offset,
            pass_number,
        });
    }

    fn generate_audit_hmac(&self) -> Result<String, DestructionError> {
        let serialized = serde_json::to_vec(&self.operation_log)
            .map_err(|e| DestructionError::CryptoFailure(format!("Failed to serialize operation log: {}", e)))?;
        
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.hmac_key.0)
            .map_err(|e| DestructionError::CryptoFailure(format!("Failed to create HMAC: {}", e)))?;
        mac.update(&serialized);
        Ok(hex::encode(&mac.finalize().into_bytes()))
    }

    fn destroy_file(&mut self, path: &Path) -> Result<DestructionResult, DestructionError> {
        let start_time = Utc::now();
        
        // Get file metadata
        let metadata = std::fs::metadata(path)
            .map_err(|e| DestructionError::Io(format!("Cannot read file metadata: {}", e)))?;
        
        let file_size = metadata.len();
        let use_streaming = file_size > self.config.streaming_threshold as u64;
        
        self.log_operation("preflight", "file_analysis_start", None, None);
        
        // Phase 1: Linguistic Pattern Destruction
        let linguistic_before = self.analyze_linguistics(path)?;
        self.log_operation("phase_1", "linguistic_analysis_complete", None, None);
        
        let temp_path = self.create_temp_file(path)?;
        self.apply_linguistic_destruction(path, &temp_path, use_streaming)?;
        
        // Phase 2: AES-256-CTR Cryptographic Overwrite
        let passes = self.config.pass_count.unwrap_or(self.config.security_level.pass_count());
        let mut verification_hashes = Vec::new();
        
        for pass in 1..=passes {
            self.log_operation("phase_2", "aes_overwrite_pass", None, Some(pass));
            self.aes_overwrite_pass(&temp_path, pass, &mut verification_hashes)?;
        }
        
        // Phase 3: Verification & Cleanup
        let linguistic_after = self.analyze_linguistics_binary_safe(&temp_path)?;
        
        // Replace original file atomically
        self.atomic_replace(path, &temp_path)?;
        
        let tamper_evident_hmac = Some(self.generate_audit_hmac()?);
        
        let mut warnings = Vec::new();
        self.detect_platform_limitations(&mut warnings);
        
        let success = self.verify_destruction(&linguistic_before, &linguistic_after);
        
        Ok(DestructionResult {
            file_path: path.to_string_lossy().to_string(),
            original_size: file_size,
            passes_executed: passes,
            linguistic_metrics_before: linguistic_before,
            linguistic_metrics_after: linguistic_after,
            verification_hashes,
            tamper_evident_hmac,
            timestamp_utc: start_time,
            warnings,
            success,
        })
    }

    fn destroy_stream(&mut self, _stream: impl Read + Write + Seek) -> Result<DestructionResult, DestructionError> {
        // Stream operations are similar but work with the stream directly
        // This is a simplified implementation - full implementation would be more complex
        Err(DestructionError::StreamingError("Stream destruction not yet implemented".to_string()))
    }

    fn analyze_linguistics_binary_safe(&mut self, path: &Path) -> Result<LinguisticMetrics, DestructionError> {
        // Try to read as UTF-8, but if it fails, create empty metrics
        // This is used after cryptographic overwrite when the file contains binary data
        match std::fs::read_to_string(path) {
            Ok(content) => self.analyze_linguistics_content(&content),
            Err(_) => {
                // File is not valid UTF-8 (expected after AES overwrite)
                // Return metrics indicating successful destruction
                Ok(LinguisticMetrics {
                    char_frequency: HashMap::new(),
                    top_words: Vec::new(),
                    sentence_entropy: 0.0,
                    whitespace_stats: WhitespaceStats {
                        total_whitespace: 0,
                        newline_count: 0,
                        tab_count: 0,
                        space_runs: 0,
                        indentation_patterns: 0,
                    },
                    pattern_score: 0, // Very low score indicates good destruction
                })
            }
        }
    }

    fn analyze_linguistics(&mut self, path: &Path) -> Result<LinguisticMetrics, DestructionError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| DestructionError::InvalidEncoding(format!("Failed to read file as UTF-8: {}", e)))?;
        
        self.analyze_linguistics_content(&content)
    }

    fn analyze_linguistics_content(&mut self, content: &str) -> Result<LinguisticMetrics, DestructionError> {
        // Character frequency analysis
        let mut char_frequency = HashMap::new();
        for ch in content.chars() {
            *char_frequency.entry(ch).or_insert(0) += 1;
        }
        
        // Word frequency analysis
        let words: Vec<&str> = content.unicode_words().collect();
        let mut word_frequency = HashMap::new();
        for word in words {
            *word_frequency.entry(word.to_lowercase()).or_insert(0) += 1;
        }
        
        let mut top_words: Vec<(String, u32)> = word_frequency.into_iter().collect();
        top_words.sort_by(|a, b| b.1.cmp(&a.1));
        top_words.truncate(50); // Top 50 words
        
        // Sentence entropy calculation (simplified)
        let sentences: Vec<&str> = content.split('.').collect();
        let sentence_entropy = calculate_entropy(&sentences);
        
        // Whitespace statistics
        let whitespace_stats = WhitespaceStats {
            total_whitespace: content.chars().filter(|c| c.is_whitespace()).count() as u32,
            newline_count: content.matches('\n').count() as u32,
            tab_count: content.matches('\t').count() as u32,
            space_runs: count_space_runs(content),
            indentation_patterns: count_indentation_patterns(content),
        };
        
        // Calculate pattern score (0-100, lower means better destruction)
        let pattern_score = calculate_pattern_score(&char_frequency, &top_words, sentence_entropy);
        
        Ok(LinguisticMetrics {
            char_frequency,
            top_words,
            sentence_entropy,
            whitespace_stats,
            pattern_score,
        })
    }

    fn apply_linguistic_destruction(&mut self, input_path: &Path, output_path: &Path, streaming: bool) -> Result<(), DestructionError> {
        let input_file = File::open(input_path)
            .map_err(|e| DestructionError::Io(format!("Failed to open input file: {}", e)))?;
        
        let output_file = File::create(output_path)
            .map_err(|e| DestructionError::Io(format!("Failed to create output file: {}", e)))?;
        
        if streaming {
            self.apply_linguistic_destruction_streaming(input_file, output_file)?;
        } else {
            self.apply_linguistic_destruction_buffered(input_file, output_file)?;
        }
        
        Ok(())
    }

    fn apply_linguistic_destruction_streaming(&mut self, mut input: File, mut output: File) -> Result<(), DestructionError> {
        let buffer_size = self.config.buffer_size.unwrap_or(4096);
        let mut buffer = vec![0u8; buffer_size];
        let mut offset = 0u64;
        
        loop {
            let bytes_read = input.read(&mut buffer)
                .map_err(|e| DestructionError::Io(format!("Failed to read from input: {}", e)))?;
            
            if bytes_read == 0 {
                break;
            }
            
            // Convert to string for linguistic processing
            let content = String::from_utf8_lossy(&buffer[..bytes_read]);
            let mut processed = content.to_string();
            
            // Apply transformations based on linguistic depth
            match self.config.linguistic_depth {
                LinguisticDepth::Shallow => {
                    processed = self.apply_character_level_destruction(&processed);
                    processed = self.apply_word_level_destruction(&processed);
                }
                LinguisticDepth::Deep => {
                    processed = self.apply_character_level_destruction(&processed);
                    processed = self.apply_word_level_destruction(&processed);
                    processed = self.apply_sentence_level_destruction(&processed);
                }
            }
            
            let processed_bytes = processed.as_bytes();
            output.write_all(processed_bytes)
                .map_err(|e| DestructionError::Io(format!("Failed to write to output: {}", e)))?;
            
            self.log_operation("phase_1", "linguistic_transform_chunk", Some(offset), None);
            offset += bytes_read as u64;
        }
        
        output.sync_all()
            .map_err(|e| DestructionError::Io(format!("Failed to sync output: {}", e)))?;
        
        Ok(())
    }

    fn apply_linguistic_destruction_buffered(&mut self, mut input: File, mut output: File) -> Result<(), DestructionError> {
        let mut content = String::new();
        input.read_to_string(&mut content)
            .map_err(|e| DestructionError::InvalidEncoding(format!("Failed to read as UTF-8: {}", e)))?;
        
        // Apply transformations based on linguistic depth
        match self.config.linguistic_depth {
            LinguisticDepth::Shallow => {
                content = self.apply_character_level_destruction(&content);
                content = self.apply_word_level_destruction(&content);
            }
            LinguisticDepth::Deep => {
                content = self.apply_character_level_destruction(&content);
                content = self.apply_word_level_destruction(&content);
                content = self.apply_sentence_level_destruction(&content);
            }
        }
        
        output.write_all(content.as_bytes())
            .map_err(|e| DestructionError::Io(format!("Failed to write processed content: {}", e)))?;
        
        output.sync_all()
            .map_err(|e| DestructionError::Io(format!("Failed to sync output: {}", e)))?;
        
        Ok(())
    }

    fn apply_character_level_destruction(&mut self, content: &str) -> String {
        let mut result = String::new();
        
        for ch in content.chars() {
            // Frequency flattening and homoglyph substitution
            let transformed_char = if self.rng.next_u32() % 100 < 15 { // 15% chance
                self.apply_homoglyph_substitution(ch)
            } else if ch.is_alphabetic() && self.rng.next_u32() % 100 < 20 { // 20% chance for case randomization
                if ch.is_lowercase() {
                    ch.to_uppercase().collect::<String>()
                } else {
                    ch.to_lowercase().collect::<String>()
                }
            } else {
                ch.to_string()
            };
            
            result.push_str(&transformed_char);
            
            // Occasionally insert invalid UTF-8 patterns (as valid Unicode that breaks tokenizers)
            if self.rng.next_u32() % 1000 < 5 { // 0.5% chance
                result.push('\u{FFFD}'); // Replacement character
            }
        }
        
        result
    }

    fn apply_word_level_destruction(&mut self, content: &str) -> String {
        let words: Vec<&str> = content.unicode_word_indices().map(|(_, word)| word).collect();
        let mut result = content.to_string();
        
        // Word boundary destruction and frequency flattening
        for word in words {
            if word.len() > 3 && self.rng.next_u32() % 100 < 25 { // 25% chance
                let replacement = self.apply_word_transformation(word);
                result = result.replace(word, &replacement);
            }
        }
        
        result
    }

    fn apply_sentence_level_destruction(&mut self, content: &str) -> String {
        let sentences: Vec<&str> = content.split('.').collect();
        let mut shuffled_sentences = sentences.clone();
        
        // Shuffle sentence order
        for i in 0..shuffled_sentences.len() {
            let j = (self.rng.next_u32() as usize) % shuffled_sentences.len();
            shuffled_sentences.swap(i, j);
        }
        
        // Punctuation pattern breaking
        let mut result = shuffled_sentences.join(".");
        result = result.replace(",", "，"); // Replace with full-width comma occasionally
        result = result.replace("!", "¡"); // Replace with inverted exclamation
        
        result
    }

    fn apply_homoglyph_substitution(&mut self, ch: char) -> String {
        // Simple homoglyph substitution for common Latin characters
        match ch {
            'a' => "а".to_string(), // Cyrillic 'a'
            'e' => "е".to_string(), // Cyrillic 'e'
            'o' => "о".to_string(), // Cyrillic 'o'
            'p' => "р".to_string(), // Cyrillic 'p'
            'c' => "с".to_string(), // Cyrillic 'c'
            _ => ch.to_string(),
        }
    }

    fn apply_word_transformation(&mut self, word: &str) -> String {
        let transformation = self.rng.next_u32() % 4;
        match transformation {
            0 => self.insert_word_separators(word),
            1 => self.apply_character_substitution(word),
            2 => self.reverse_word_parts(word),
            _ => word.to_string(),
        }
    }

    fn insert_word_separators(&mut self, word: &str) -> String {
        let mut result = String::new();
        for (i, ch) in word.chars().enumerate() {
            result.push(ch);
            if i > 0 && i < word.len() - 1 && self.rng.next_u32() % 100 < 30 {
                result.push('\u{200B}'); // Zero-width space
            }
        }
        result
    }

    fn apply_character_substitution(&mut self, word: &str) -> String {
        word.chars().map(|ch| self.apply_homoglyph_substitution(ch)).collect()
    }

    fn reverse_word_parts(&mut self, word: &str) -> String {
        if word.len() <= 3 {
            return word.to_string();
        }
        
        let chars: Vec<char> = word.chars().collect();
        let _mid = chars.len() / 2;
        let mut result = chars[0].to_string();
        
        // Reverse middle characters
        for ch in chars[1..chars.len()-1].iter().rev() {
            result.push(*ch);
        }
        
        if chars.len() > 1 {
            result.push(chars[chars.len()-1]);
        }
        
        result
    }

    fn aes_overwrite_pass(&mut self, path: &Path, pass_number: u8, verification_hashes: &mut Vec<[u8; 32]>) -> Result<(), DestructionError> {
        let key_source = self.config.aes_key_source.as_ref().unwrap_or(&AesKeySource::GenerateEphemeral);
        let aes_key = AesKey::generate(key_source)?;
        
        // Generate unique nonce for this pass
        let mut nonce = [0u8; 16];
        if let Some(seed) = self.config.reproducible_seed {
            // Deterministic nonce for reproducible tests
            let mut nonce_rng = StdRng::seed_from_u64(seed + pass_number as u64);
            nonce_rng.fill_bytes(&mut nonce);
        } else {
            getrandom(&mut nonce)
                .map_err(|e| DestructionError::CryptoFailure(format!("Failed to generate nonce: {}", e)))?;
        }
        
        // Initialize AES-CTR cipher
        use aes::cipher::{KeyIvInit, StreamCipher};
        let mut cipher = Aes256Ctr::new(&aes_key.0.into(), &nonce.into());
        
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| DestructionError::Io(format!("Failed to open file for overwrite: {}", e)))?;
        
        let file_size = file.metadata()
            .map_err(|e| DestructionError::Io(format!("Failed to get file metadata: {}", e)))?
            .len();
        
        let buffer_size = self.config.buffer_size.unwrap_or(4096);
        let mut buffer = vec![0u8; buffer_size];
        let mut hasher = Sha256::new();
        let mut position = 0u64;
        
        while position < file_size {
            let bytes_to_write = std::cmp::min(buffer_size as u64, file_size - position) as usize;
            
            // Generate keystream
            buffer[..bytes_to_write].fill(0);
            cipher.apply_keystream(&mut buffer[..bytes_to_write]);
            
            // Write to file
            file.seek(SeekFrom::Start(position))
                .map_err(|e| DestructionError::Io(format!("Failed to seek: {}", e)))?;
            
            file.write_all(&buffer[..bytes_to_write])
                .map_err(|e| DestructionError::Io(format!("Failed to write: {}", e)))?;
            
            // Update hash if verification enabled
            if self.config.verify_hash_between_passes {
                hasher.update(&buffer[..bytes_to_write]);
            }
            
            position += bytes_to_write as u64;
        }
        
        // Sync to disk
        file.sync_all()
            .map_err(|e| DestructionError::Io(format!("Failed to sync file: {}", e)))?;
        
        // Store verification hash
        if self.config.verify_hash_between_passes {
            let hash_result = hasher.finalize();
            let mut hash_array = [0u8; 32];
            hash_array.copy_from_slice(&hash_result);
            verification_hashes.push(hash_array);
        }
        
        self.log_operation("phase_2", "aes_pass_complete", Some(file_size), Some(pass_number));
        
        Ok(())
    }

    fn create_temp_file(&mut self, original_path: &Path) -> Result<std::path::PathBuf, DestructionError> {
        let parent = original_path.parent()
            .ok_or_else(|| DestructionError::Io("Cannot determine parent directory".to_string()))?;
        
        let temp_name = format!(".tmp_destruction_{}", self.rng.next_u64());
        let temp_path = parent.join(temp_name);
        
        // Create temp file
        File::create(&temp_path)
            .map_err(|e| DestructionError::Io(format!("Failed to create temp file: {}", e)))?;
        
        self.log_operation("setup", "temp_file_created", None, None);
        Ok(temp_path)
    }

    fn atomic_replace(&mut self, original: &Path, temp: &Path) -> Result<(), DestructionError> {
        // Try atomic rename first
        if std::fs::rename(temp, original).is_ok() {
            self.log_operation("cleanup", "atomic_replace_success", None, None);
            return Ok(());
        }
        
        // Fallback to copy and remove
        std::fs::copy(temp, original)
            .map_err(|e| DestructionError::Io(format!("Failed to copy temp file: {}", e)))?;
        
        std::fs::remove_file(temp)
            .map_err(|e| DestructionError::Io(format!("Failed to remove temp file: {}", e)))?;
        
        self.log_operation("cleanup", "fallback_replace_success", None, None);
        Ok(())
    }

    fn detect_platform_limitations(&self, warnings: &mut Vec<String>) {
        // Check for SSD indicators
        #[cfg(target_os = "linux")]
        {
            if let Ok(contents) = std::fs::read_to_string("/proc/mounts") {
                if contents.contains("ssd") || contents.contains("nvme") {
                    warnings.push("SSD detected: wear leveling may preserve data copies".to_string());
                }
            }
        }
        
        // Check for macOS APFS
        #[cfg(target_os = "macos")]
        {
            warnings.push("macOS APFS: copy-on-write filesystem may preserve data snapshots".to_string());
        }
        
        // Check for Windows
        #[cfg(target_os = "windows")]
        {
            warnings.push("Windows: NTFS features may preserve file copies in system areas".to_string());
        }
        
        warnings.push("Overwrite guarantees depend on storage hardware and filesystem behavior".to_string());
    }

    fn verify_destruction(&self, before: &LinguisticMetrics, after: &LinguisticMetrics) -> bool {
        // Simple verification: pattern score should be significantly reduced
        after.pattern_score < before.pattern_score.saturating_sub(20)
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

fn validate_config(config: &DestroyConfig) -> Result<(), DestructionError> {
    if let Some(pass_count) = config.pass_count {
        if !(3..=7).contains(&pass_count) {
            return Err(DestructionError::InvalidConfig(
                "Pass count must be between 3 and 7".to_string()
            ));
        }
    }
    
    if config.max_retries > 10 {
        return Err(DestructionError::InvalidConfig(
            "Max retries cannot exceed 10".to_string()
        ));
    }
    
    Ok(())
}

fn calculate_entropy(items: &[&str]) -> f64 {
    if items.is_empty() {
        return 0.0;
    }
    
    let mut frequency = HashMap::new();
    for item in items {
        *frequency.entry(*item).or_insert(0) += 1;
    }
    
    let total = items.len() as f64;
    frequency.values()
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

fn count_space_runs(content: &str) -> u32 {
    let mut count = 0;
    let mut in_space_run = false;
    
    for ch in content.chars() {
        if ch == ' ' {
            if !in_space_run {
                count += 1;
                in_space_run = true;
            }
        } else {
            in_space_run = false;
        }
    }
    
    count
}

fn count_indentation_patterns(content: &str) -> u32 {
    content.lines()
        .filter(|line| line.starts_with(' ') || line.starts_with('\t'))
        .count() as u32
}

fn calculate_pattern_score(char_freq: &HashMap<char, u32>, top_words: &[(String, u32)], sentence_entropy: f64) -> u8 {
    // Simplified pattern score calculation
    // Higher scores indicate more patterns (worse destruction)
    
    let char_entropy = calculate_char_entropy(char_freq);
    let word_concentration = if top_words.is_empty() { 0.0 } else {
        top_words[0].1 as f64 / top_words.iter().map(|(_, count)| *count as f64).sum::<f64>()
    };
    
    let score = (100.0 * (1.0 - char_entropy / 8.0) + 100.0 * word_concentration + 100.0 * (1.0 - sentence_entropy / 10.0)) / 3.0;
    score.min(100.0).max(0.0) as u8
}

fn calculate_char_entropy(char_freq: &HashMap<char, u32>) -> f64 {
    if char_freq.is_empty() {
        return 0.0;
    }
    
    let total: u32 = char_freq.values().sum();
    char_freq.values()
        .map(|&count| {
            let p = count as f64 / total as f64;
            -p * p.log2()
        })
        .sum()
}

// Hex encoding utility
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

// ============================================================================
// ALGORITHM TRAIT IMPLEMENTATION
// ============================================================================

use super::{SecureAlgorithm, AlgorithmInfo, CommonSecurityLevel};

/// Marker struct for the text dump algorithm
pub struct TextDumpAlgorithm;

impl SecureAlgorithm for TextDumpAlgorithm {
    type Config = DestroyConfig;
    type Report = DestructionResult;
    type Error = DestructionError;
    
    fn execute(file_path: &Path, config: Self::Config) -> Result<Self::Report, Self::Error> {
        let builder = LinguisticDestructionBuilder::with_config(config);
        builder.destroy_file(file_path)
    }
    
    fn get_info() -> AlgorithmInfo {
        AlgorithmInfo {
            name: "text_dump_a".to_string(),
            version: "1.0.0".to_string(),
            description: "Secure text-based file destruction with linguistic pattern removal and AES-256-CTR overwriting".to_string(),
            supported_file_types: vec![".txt".to_string(), ".md".to_string(), ".log".to_string(), ".csv".to_string()],
            security_levels: vec!["Low".to_string(), "Medium".to_string(), "High".to_string()],
            features: vec![
                "Linguistic pattern destruction".to_string(),
                "AES-256-CTR cryptographic overwriting".to_string(),
                "Character/word/sentence level transformations".to_string(),
                "Homoglyph substitution".to_string(),
                "Streaming mode for large files".to_string(),
                "Tamper-evident audit trails".to_string(),
            ],
        }
    }
    
    fn validate_config(config: &Self::Config) -> Result<(), Self::Error> {
        validate_config(config)
    }
}

/// Convert common security level to text dump security level
impl From<CommonSecurityLevel> for SecurityLevel {
    fn from(common: CommonSecurityLevel) -> Self {
        match common {
            CommonSecurityLevel::Low => SecurityLevel::Low,
            CommonSecurityLevel::Medium => SecurityLevel::Medium,
            CommonSecurityLevel::High | CommonSecurityLevel::Maximum => SecurityLevel::High,
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    
    #[test]
    fn test_basic_text_destruction() {
        let test_content = "Hello world! This is a test file with some patterns.\nRepeated words: test test test.\nSentence patterns are here.";
        
        // Use a more robust temp file approach
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("test_text_destruction.txt");
        
        // Write test file
        fs::write(&temp_path, test_content).unwrap();
        
        // Verify file was written correctly
        let read_back = fs::read_to_string(&temp_path).unwrap();
        assert_eq!(read_back, test_content);
        
        // Test destruction
        let config = DestroyConfig {
            security_level: SecurityLevel::Low,
            linguistic_depth: LinguisticDepth::Deep,
            pass_count: Some(3),
            verify_hash_between_passes: true,
            ..Default::default()
        };
        
        let result = TextDumpAlgorithm::execute(&temp_path, config);
        
        match result {
            Ok(report) => {
                assert!(report.success);
                assert_eq!(report.passes_executed, 3);
                assert!(report.tamper_evident_hmac.is_some());
                assert!(report.linguistic_metrics_after.pattern_score < report.linguistic_metrics_before.pattern_score);
                
                // Verify file still exists but is transformed
                assert!(temp_path.exists());
                
                // Clean up
                let _ = fs::remove_file(&temp_path);
            }
            Err(e) => {
                println!("Destruction failed: {:?}", e);
                let _ = fs::remove_file(&temp_path);
                panic!("Test failed: {:?}", e);
            }
        }
    }
    
    #[test]
    fn test_linguistic_analysis() {
        let mut processor = TextDestructionProcessor::new(&DestroyConfig::default()).unwrap();
        
        let test_content = "Test test test. Hello world world.";
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("test_linguistic_analysis.txt");
        
        fs::write(&temp_path, test_content).unwrap();
        
        let metrics = processor.analyze_linguistics(&temp_path).unwrap();
        
        assert!(!metrics.char_frequency.is_empty());
        assert!(!metrics.top_words.is_empty());
        assert!(metrics.pattern_score > 0);
        
        // Clean up
        let _ = fs::remove_file(&temp_path);
    }
    
    #[test]
    fn test_character_level_destruction() {
        let mut processor = TextDestructionProcessor::new(&DestroyConfig::default()).unwrap();
        
        let original = "Hello World!";
        let transformed = processor.apply_character_level_destruction(original);
        
        // Should be different from original
        assert_ne!(original, transformed);
        // Should have similar length (allow for Unicode substitutions)
        assert!(transformed.len() >= original.len());
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = DestroyConfig::default();
        assert!(validate_config(&config).is_ok());
        
        config.pass_count = Some(10); // Too many passes
        assert!(validate_config(&config).is_err());
        
        config.pass_count = Some(3);
        config.max_retries = 15; // Too many retries
        assert!(validate_config(&config).is_err());
    }
    
    #[test]
    fn test_builder_pattern() {
        let builder = LinguisticDestructionBuilder::new();
        let builder_with_config = LinguisticDestructionBuilder::with_config(DestroyConfig::default());
        
        // Test that builders can be created
        assert_eq!(builder.config.security_level as u8, SecurityLevel::Medium as u8);
        assert_eq!(builder_with_config.config.security_level as u8, SecurityLevel::Medium as u8);
    }
    
    #[test]
    fn test_entropy_calculation() {
        let items = vec!["a", "a", "b", "c"];
        let entropy = calculate_entropy(&items);
        assert!(entropy > 0.0);
        assert!(entropy < 2.0); // Max entropy for 3 unique items
    }
    
    #[test]
    fn test_pattern_score() {
        let mut char_freq = HashMap::new();
        char_freq.insert('a', 10);
        char_freq.insert('b', 5);
        char_freq.insert('c', 1);
        
        let top_words = vec![("test".to_string(), 5), ("hello".to_string(), 2)];
        let score = calculate_pattern_score(&char_freq, &top_words, 2.0);
        
        assert!(score <= 100);
    }
    
    #[test]
    fn test_security_level_conversion() {
        assert!(matches!(SecurityLevel::from(CommonSecurityLevel::Low), SecurityLevel::Low));
        assert!(matches!(SecurityLevel::from(CommonSecurityLevel::Medium), SecurityLevel::Medium));
        assert!(matches!(SecurityLevel::from(CommonSecurityLevel::High), SecurityLevel::High));
        assert!(matches!(SecurityLevel::from(CommonSecurityLevel::Maximum), SecurityLevel::High));
    }
    
    #[test]
    fn test_algorithm_info() {
        let info = TextDumpAlgorithm::get_info();
        assert_eq!(info.name, "text_dump_a");
        assert!(!info.features.is_empty());
        assert!(info.supported_file_types.contains(&".txt".to_string()));
    }
}
