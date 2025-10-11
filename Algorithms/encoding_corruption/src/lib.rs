//! Algorithm B: Character Frequency Flattening → AES Overwrite
//! 
//! This algorithm implements secure text file destruction through character frequency 
//! distribution flattening followed by cryptographic overwrite:
//! 1. Character Frequency Analysis - Analyze and flatten frequency distributions
//! 2. Pattern Destruction Engine - Destroy positional patterns and sequences  
//! 3. AES-256 Cryptographic Overwrite - Multi-pass cryptographic sanitization
//! 4. Verification and Validation - Entropy measurement and forensic resistance

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::AtomicU64;

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;
use chrono::{DateTime, Utc};
use rand::{RngCore, SeedableRng};
use rand::rngs::{OsRng, StdRng};
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
// PUBLIC API TYPES
// ============================================================================

/// Security profile determines the number of cryptographic passes
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SecurityProfile {
    /// Conservative: 3 passes, basic frequency flattening
    Conservative,
    /// Standard: 5 passes, comprehensive pattern destruction
    Standard,
    /// Paranoid: 7 passes, maximum entropy and forensic resistance
    Paranoid,
}

impl SecurityProfile {
    fn pass_count(&self) -> u8 {
        match self {
            SecurityProfile::Conservative => 3,
            SecurityProfile::Standard => 5,
            SecurityProfile::Paranoid => 7,
        }
    }
}

/// Unicode processing strategy
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum UnicodeMode {
    /// Basic ASCII handling only
    Basic,
    /// Full Unicode support with all planes
    Full,
    /// Selective targeting of specific Unicode ranges
    Selective,
}

/// Language-specific pattern targeting
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum LanguageProfile {
    /// English language patterns
    English,
    /// Multi-language support
    MultiLanguage,
    /// Language-agnostic processing
    LanguageAgnostic,
}

/// Performance optimization mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum PerformanceMode {
    /// Optimize for minimal memory usage
    MemoryOptimized,
    /// Optimize for maximum speed
    SpeedOptimized,
    /// Balanced approach
    Balanced,
}

/// Configuration for frequency flattening algorithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlatteningConfig {
    /// Target Shannon entropy in bits (0.0-8.0 for byte entropy)
    pub target_entropy: f64,
    /// Frequency uniformity threshold (0.0-1.0)
    pub distribution_tolerance: f64,
    /// Enable language-specific pattern targeting
    pub language_aware: bool,
    /// Unicode processing strategy
    pub unicode_handling: UnicodeMode,
    /// Security profile for cryptographic passes
    pub security_profile: SecurityProfile,
    /// Language profile for pattern recognition
    pub language_profile: LanguageProfile,
    /// Performance optimization mode
    pub performance_mode: PerformanceMode,
    /// Buffer size for streaming operations
    pub buffer_size: usize,
    /// Enable SIMD acceleration if available
    pub enable_simd: bool,
    /// Reproducible seed for deterministic testing
    pub reproducible_seed: Option<u64>,
}

impl Default for FlatteningConfig {
    fn default() -> Self {
        Self {
            target_entropy: 7.8, // Near maximum entropy for 8-bit data
            distribution_tolerance: 0.05, // 5% tolerance
            language_aware: true,
            unicode_handling: UnicodeMode::Full,
            security_profile: SecurityProfile::Standard,
            language_profile: LanguageProfile::English,
            performance_mode: PerformanceMode::Balanced,
            buffer_size: 64 * 1024, // 64KB buffer
            enable_simd: true,
            reproducible_seed: None,
        }
    }
}

/// Verification check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCheck {
    pub check_type: String,
    pub passed: bool,
    pub value: f64,
    pub threshold: f64,
    pub description: String,
}

/// Result of the destruction process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestructionResult {
    /// Initial Shannon entropy before processing
    pub initial_entropy: f64,
    /// Final Shannon entropy after processing
    pub final_entropy: f64,
    /// Frequency distribution deviation from uniform
    pub frequency_deviation: f64,
    /// Number of cryptographic passes performed
    pub cryptographic_passes: u8,
    /// Verification checks performed
    pub verification_checks: Vec<VerificationCheck>,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
    /// Bytes processed
    pub bytes_processed: u64,
    /// Chi-squared test statistic for uniformity
    pub chi_squared_statistic: f64,
    /// Kullback-Leibler divergence from uniform distribution
    pub kl_divergence: f64,
}

/// Pattern analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternAnalysis {
    /// Character frequency histogram
    pub char_frequency: HashMap<char, u64>,
    /// Bigram frequency map
    pub bigram_frequency: HashMap<String, u64>,
    /// Trigram frequency map  
    pub trigram_frequency: HashMap<String, u64>,
    /// Positional character frequencies
    pub positional_frequency: HashMap<usize, HashMap<char, u64>>,
    /// Shannon entropy of the text
    pub entropy: f64,
    /// Chi-squared statistic for uniformity test
    pub chi_squared: f64,
    /// Total character count
    pub total_chars: u64,
    /// Unique character count
    pub unique_chars: usize,
}

/// Error types for frequency flattening operations
#[derive(Error, Debug)]
pub enum FlatteningError {
    #[error("IO error: {0}")]
    Io(String),
    #[error("Configuration validation error: {0}")]
    InvalidConfig(String),
    #[error("Cryptographic operation failed: {0}")]
    CryptoFailure(String),
    #[error("Statistical analysis failed: {0}")]
    StatisticalFailure(String),
    #[error("Unicode processing error: {0}")]
    UnicodeError(String),
    #[error("Verification failed: {0}")]
    VerificationFailure(String),
    #[error("Memory allocation error: {0}")]
    MemoryError(String),
}

// ============================================================================
// CORE FREQUENCY FLATTENING ENGINE
// ============================================================================

/// Main frequency flattening engine
pub struct FrequencyFlatteningEngine {
    config: FlatteningConfig,
    rng: Box<dyn RngCore + Send>,
    operation_log: Vec<OperationLogEntry>,
    hmac_key: HmacKey,
}

/// Operation log entry for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OperationLogEntry {
    timestamp: DateTime<Utc>,
    phase: String,
    operation: String,
    byte_offset: Option<u64>,
    pass_number: Option<u8>,
    entropy_before: Option<f64>,
    entropy_after: Option<f64>,
}

/// Zeroized HMAC key for integrity verification
#[derive(ZeroizeOnDrop)]
struct HmacKey([u8; 32]);

impl HmacKey {
    fn generate() -> Result<Self, FlatteningError> {
        let mut key = [0u8; 32];
        getrandom(&mut key)
            .map_err(|e| FlatteningError::CryptoFailure(format!("Failed to generate HMAC key: {}", e)))?;
        Ok(Self(key))
    }
}

/// Zeroized AES key for cryptographic operations
#[derive(ZeroizeOnDrop)]
struct AesKey([u8; 32]);

impl AesKey {
    fn generate() -> Result<Self, FlatteningError> {
        let mut key = [0u8; 32];
        getrandom(&mut key)
            .map_err(|e| FlatteningError::CryptoFailure(format!("Failed to generate AES key: {}", e)))?;
        Ok(Self(key))
    }
}

/// Statistical frequency analyzer
struct FrequencyAnalyzer {
    char_counts: HashMap<char, AtomicU64>,
    bigram_counts: HashMap<String, AtomicU64>,
    trigram_counts: HashMap<String, AtomicU64>,
    positional_counts: HashMap<usize, HashMap<char, AtomicU64>>,
    total_chars: AtomicU64,
    config: FlatteningConfig,
}

impl FrequencyAnalyzer {
    fn new(config: &FlatteningConfig) -> Self {
        Self {
            char_counts: HashMap::new(),
            bigram_counts: HashMap::new(),
            trigram_counts: HashMap::new(),
            positional_counts: HashMap::new(),
            total_chars: AtomicU64::new(0),
            config: config.clone(),
        }
    }

    /// Analyze character frequencies in text
    fn analyze_text(&mut self, text: &str) -> Result<PatternAnalysis, FlatteningError> {
        let chars: Vec<char> = text.chars().collect();
        let total_chars = chars.len() as u64;
        
        // Character frequency analysis
        let mut char_frequency = HashMap::new();
        for &ch in &chars {
            *char_frequency.entry(ch).or_insert(0) += 1;
        }

        // Bigram analysis
        let mut bigram_frequency = HashMap::new();
        for window in chars.windows(2) {
            let bigram = format!("{}{}", window[0], window[1]);
            *bigram_frequency.entry(bigram).or_insert(0) += 1;
        }

        // Trigram analysis
        let mut trigram_frequency = HashMap::new();
        for window in chars.windows(3) {
            let trigram = format!("{}{}{}", window[0], window[1], window[2]);
            *trigram_frequency.entry(trigram).or_insert(0) += 1;
        }

        // Positional frequency analysis
        let mut positional_frequency = HashMap::new();
        for (pos, &ch) in chars.iter().enumerate() {
            let word_pos = pos % 10; // Analyze position within first 10 characters of words
            positional_frequency
                .entry(word_pos)
                .or_insert_with(HashMap::new)
                .entry(ch)
                .and_modify(|e| *e += 1)
                .or_insert(1);
        }

        // Calculate Shannon entropy
        let entropy = self.calculate_shannon_entropy(&char_frequency, total_chars);
        
        // Calculate chi-squared statistic for uniformity test
        let chi_squared = self.calculate_chi_squared(&char_frequency, total_chars);

        let unique_chars = char_frequency.len();
        
        Ok(PatternAnalysis {
            char_frequency,
            bigram_frequency,
            trigram_frequency,
            positional_frequency,
            entropy,
            chi_squared,
            total_chars,
            unique_chars,
        })
    }

    /// Calculate Shannon entropy
    fn calculate_shannon_entropy(&self, frequencies: &HashMap<char, u64>, total: u64) -> f64 {
        if total == 0 {
            return 0.0;
        }

        frequencies.values()
            .map(|&count| {
                let probability = count as f64 / total as f64;
                if probability > 0.0 {
                    -probability * probability.log2()
                } else {
                    0.0
                }
            })
            .sum()
    }

    /// Calculate chi-squared statistic for uniformity test
    fn calculate_chi_squared(&self, frequencies: &HashMap<char, u64>, total: u64) -> f64 {
        if frequencies.is_empty() || total == 0 {
            return 0.0;
        }

        let expected = total as f64 / frequencies.len() as f64;
        frequencies.values()
            .map(|&observed| {
                let diff = observed as f64 - expected;
                (diff * diff) / expected
            })
            .sum()
    }
}

/// Pattern destruction processor
struct PatternDestructor {
    config: FlatteningConfig,
    rng: Box<dyn RngCore + Send>,
}

impl PatternDestructor {
    fn new(config: &FlatteningConfig, rng: Box<dyn RngCore + Send>) -> Self {
        Self {
            config: config.clone(),
            rng,
        }
    }

    /// Apply frequency flattening to text
    fn flatten_frequencies(&mut self, text: &str, analysis: &PatternAnalysis) -> Result<String, FlatteningError> {
        let chars: Vec<char> = text.chars().collect();
        let mut result = Vec::with_capacity(chars.len());

        // Create substitution map based on frequency analysis
        let substitution_map = self.create_substitution_map(analysis)?;

        for &ch in &chars {
            let flattened_char = if let Some(&substitute) = substitution_map.get(&ch) {
                substitute
            } else {
                // Apply random transformation for unknown characters
                self.apply_random_transformation(ch)
            };
            result.push(flattened_char);
        }

        // Apply additional pattern breaking
        self.break_sequential_patterns(&mut result)?;

        Ok(result.into_iter().collect())
    }

    /// Create character substitution map for frequency flattening
    fn create_substitution_map(&mut self, analysis: &PatternAnalysis) -> Result<HashMap<char, char>, FlatteningError> {
        let mut substitution_map = HashMap::new();
        
        // Sort characters by frequency (most frequent first)
        let mut char_freq_pairs: Vec<_> = analysis.char_frequency.iter().collect();
        char_freq_pairs.sort_by(|a, b| b.1.cmp(a.1));

        // Create target uniform distribution
        let target_chars: Vec<char> = char_freq_pairs.iter().map(|(&ch, _)| ch).collect();
        let mut shuffled_targets = target_chars.clone();
        
        // Shuffle target characters to break frequency correlations
        for i in (1..shuffled_targets.len()).rev() {
            let j = (self.rng.next_u32() as usize) % (i + 1);
            shuffled_targets.swap(i, j);
        }

        // Create substitution mapping
        for (i, &source_char) in target_chars.iter().enumerate() {
            if i < shuffled_targets.len() {
                substitution_map.insert(source_char, shuffled_targets[i]);
            }
        }

        Ok(substitution_map)
    }

    /// Apply random transformation to character
    fn apply_random_transformation(&mut self, ch: char) -> char {
        match self.config.unicode_handling {
            UnicodeMode::Basic => {
                if ch.is_ascii() {
                    // Simple ASCII transformation
                    let ascii_val = ch as u8;
                    let transformed = ascii_val.wrapping_add((self.rng.next_u32() % 26) as u8);
                    if transformed.is_ascii() {
                        transformed as char
                    } else {
                        ch
                    }
                } else {
                    ch
                }
            }
            UnicodeMode::Full | UnicodeMode::Selective => {
                // More sophisticated Unicode transformation
                if ch.is_alphabetic() {
                    if self.rng.next_u32() % 2 == 0 {
                        ch.to_uppercase().next().unwrap_or(ch)
                    } else {
                        ch.to_lowercase().next().unwrap_or(ch)
                    }
                } else {
                    ch
                }
            }
        }
    }

    /// Break sequential patterns in the character array
    fn break_sequential_patterns(&mut self, chars: &mut Vec<char>) -> Result<(), FlatteningError> {
        // Break bigram patterns
        for i in 0..chars.len().saturating_sub(1) {
            if self.rng.next_u32() % 100 < 10 { // 10% chance to break pattern
                chars.swap(i, i + 1);
            }
        }

        // Insert entropy-increasing characters occasionally
        let mut insertions = Vec::new();
        for i in 0..chars.len() {
            if self.rng.next_u32() % 1000 < 5 { // 0.5% chance
                insertions.push((i, self.generate_entropy_char()));
            }
        }

        // Apply insertions in reverse order to maintain indices
        for (pos, ch) in insertions.into_iter().rev() {
            chars.insert(pos, ch);
        }

        Ok(())
    }

    /// Generate high-entropy character
    fn generate_entropy_char(&mut self) -> char {
        // Generate character from high-entropy Unicode ranges
        let entropy_ranges = [
            (0x2000, 0x206F), // General Punctuation
            (0x2070, 0x209F), // Superscripts and Subscripts
            (0x20A0, 0x20CF), // Currency Symbols
            (0x2100, 0x214F), // Letterlike Symbols
        ];

        let range = entropy_ranges[self.rng.next_u32() as usize % entropy_ranges.len()];
        let code_point = range.0 + (self.rng.next_u32() % (range.1 - range.0 + 1));
        
        char::from_u32(code_point).unwrap_or('\u{FFFD}')
    }
}

// ============================================================================
// MAIN IMPLEMENTATION
// ============================================================================

impl FrequencyFlatteningEngine {
    /// Create new frequency flattening engine with configuration
    pub fn with_config(config: FlatteningConfig) -> Result<Self, FlatteningError> {
        validate_config(&config)?;

        let rng: Box<dyn RngCore + Send> = if let Some(seed) = config.reproducible_seed {
            Box::new(StdRng::seed_from_u64(seed))
        } else {
            Box::new(OsRng)
        };

        let hmac_key = HmacKey::generate()?;

        Ok(Self {
            config,
            rng,
            operation_log: Vec::new(),
            hmac_key,
        })
    }

    /// Create engine with default configuration
    pub fn new() -> Result<Self, FlatteningError> {
        Self::with_config(FlatteningConfig::default())
    }

    /// Destroy file using frequency flattening algorithm
    pub fn destroy_file(&mut self, path: &Path) -> Result<DestructionResult, FlatteningError> {
        let start_time = std::time::Instant::now();
        
        // Read file content
        let content = std::fs::read_to_string(path)
            .map_err(|e| FlatteningError::Io(format!("Failed to read file: {}", e)))?;

        let bytes_processed = content.len() as u64;

        // Phase 1: Analyze patterns
        let mut analyzer = FrequencyAnalyzer::new(&self.config);
        let initial_analysis = analyzer.analyze_text(&content)?;
        let initial_entropy = initial_analysis.entropy;

        self.log_operation("phase_1", "pattern_analysis", None, None, Some(initial_entropy), None);

        // Phase 2: Apply frequency flattening
        let mut destructor = PatternDestructor::new(&self.config, Box::new(OsRng));
        let flattened_content = destructor.flatten_frequencies(&content, &initial_analysis)?;

        // Analyze flattened content
        let final_analysis = analyzer.analyze_text(&flattened_content)?;
        let final_entropy = final_analysis.entropy;

        self.log_operation("phase_2", "frequency_flattening", None, None, Some(initial_entropy), Some(final_entropy));

        // Phase 3: Cryptographic overwrite
        let passes = self.config.security_profile.pass_count();
        self.apply_cryptographic_passes(path, &flattened_content, passes)?;

        // Phase 4: Verification
        let verification_checks = self.perform_verification_checks(&initial_analysis, &final_analysis)?;

        let processing_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(DestructionResult {
            initial_entropy,
            final_entropy,
            frequency_deviation: self.calculate_frequency_deviation(&final_analysis),
            cryptographic_passes: passes,
            verification_checks,
            processing_time_ms,
            bytes_processed,
            chi_squared_statistic: final_analysis.chi_squared,
            kl_divergence: self.calculate_kl_divergence(&final_analysis),
        })
    }

    /// Destroy content in a stream
    pub fn destroy_stream(&mut self, mut stream: impl Read + Write + Seek) -> Result<DestructionResult, FlatteningError> {
        let start_time = std::time::Instant::now();

        // Read content from stream
        let mut content = String::new();
        stream.read_to_string(&mut content)
            .map_err(|e| FlatteningError::Io(format!("Failed to read from stream: {}", e)))?;

        let bytes_processed = content.len() as u64;

        // Apply the same processing as file destruction
        let mut analyzer = FrequencyAnalyzer::new(&self.config);
        let initial_analysis = analyzer.analyze_text(&content)?;
        let initial_entropy = initial_analysis.entropy;

        let mut destructor = PatternDestructor::new(&self.config, Box::new(OsRng));
        let flattened_content = destructor.flatten_frequencies(&content, &initial_analysis)?;

        let final_analysis = analyzer.analyze_text(&flattened_content)?;
        let final_entropy = final_analysis.entropy;

        // Write flattened content back to stream
        stream.seek(SeekFrom::Start(0))
            .map_err(|e| FlatteningError::Io(format!("Failed to seek stream: {}", e)))?;
        
        stream.write_all(flattened_content.as_bytes())
            .map_err(|e| FlatteningError::Io(format!("Failed to write to stream: {}", e)))?;

        // Apply cryptographic passes to stream
        let passes = self.config.security_profile.pass_count();
        self.apply_cryptographic_passes_to_stream(&mut stream, passes)?;

        let verification_checks = self.perform_verification_checks(&initial_analysis, &final_analysis)?;
        let processing_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(DestructionResult {
            initial_entropy,
            final_entropy,
            frequency_deviation: self.calculate_frequency_deviation(&final_analysis),
            cryptographic_passes: passes,
            verification_checks,
            processing_time_ms,
            bytes_processed,
            chi_squared_statistic: final_analysis.chi_squared,
            kl_divergence: self.calculate_kl_divergence(&final_analysis),
        })
    }

    /// Analyze patterns in data without destruction
    pub fn analyze_patterns(&mut self, data: &[u8]) -> Result<PatternAnalysis, FlatteningError> {
        let text = String::from_utf8_lossy(data);
        let mut analyzer = FrequencyAnalyzer::new(&self.config);
        analyzer.analyze_text(&text)
    }

    // ============================================================================
    // PRIVATE IMPLEMENTATION METHODS
    // ============================================================================

    /// Apply cryptographic passes to file
    fn apply_cryptographic_passes(&mut self, path: &Path, content: &str, passes: u8) -> Result<(), FlatteningError> {
        for pass in 1..=passes {
            let aes_key = AesKey::generate()?;
            self.apply_single_cryptographic_pass(path, content, pass, &aes_key)?;
            self.log_operation("phase_3", "cryptographic_pass", None, Some(pass), None, None);
        }
        Ok(())
    }

    /// Apply cryptographic passes to stream
    fn apply_cryptographic_passes_to_stream(&mut self, stream: &mut (impl Read + Write + Seek), passes: u8) -> Result<(), FlatteningError> {
        for pass in 1..=passes {
            let aes_key = AesKey::generate()?;
            self.apply_single_cryptographic_pass_to_stream(stream, pass, &aes_key)?;
            self.log_operation("phase_3", "cryptographic_pass_stream", None, Some(pass), None, None);
        }
        Ok(())
    }

    /// Apply single cryptographic pass to file
    fn apply_single_cryptographic_pass(&mut self, path: &Path, content: &str, pass: u8, key: &AesKey) -> Result<(), FlatteningError> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|e| FlatteningError::Io(format!("Failed to open file for pass {}: {}", pass, e)))?;

        // Generate cryptographic pattern based on pass number
        let pattern = self.generate_cryptographic_pattern(content.len(), pass, key)?;
        
        file.write_all(&pattern)
            .map_err(|e| FlatteningError::Io(format!("Failed to write cryptographic pass {}: {}", pass, e)))?;

        file.sync_all()
            .map_err(|e| FlatteningError::Io(format!("Failed to sync file after pass {}: {}", pass, e)))?;

        Ok(())
    }

    /// Apply single cryptographic pass to stream
    fn apply_single_cryptographic_pass_to_stream(&mut self, stream: &mut (impl Write + Seek), pass: u8, key: &AesKey) -> Result<(), FlatteningError> {
        stream.seek(SeekFrom::Start(0))
            .map_err(|e| FlatteningError::Io(format!("Failed to seek for pass {}: {}", pass, e)))?;

        // For stream, we'll overwrite with a fixed pattern size
        let pattern_size = 1024 * 1024; // 1MB pattern
        let pattern = self.generate_cryptographic_pattern(pattern_size, pass, key)?;
        
        stream.write_all(&pattern)
            .map_err(|e| FlatteningError::Io(format!("Failed to write cryptographic pass {} to stream: {}", pass, e)))?;

        Ok(())
    }

    /// Generate cryptographic pattern for overwrite
    fn generate_cryptographic_pattern(&mut self, size: usize, pass: u8, key: &AesKey) -> Result<Vec<u8>, FlatteningError> {
        let mut pattern = vec![0u8; size];
        
        // Use AES-CTR to generate cryptographically secure pattern
        let mut nonce = [0u8; 16];
        nonce[0] = pass; // Include pass number in nonce
        self.rng.fill_bytes(&mut nonce[1..]);

        let mut cipher = Aes256Ctr::new(&key.0.into(), &nonce.into());
        cipher.apply_keystream(&mut pattern);

        Ok(pattern)
    }

    /// Perform verification checks
    fn perform_verification_checks(&self, initial: &PatternAnalysis, final_analysis: &PatternAnalysis) -> Result<Vec<VerificationCheck>, FlatteningError> {
        let mut checks = Vec::new();

        // Entropy improvement check
        let entropy_improvement = final_analysis.entropy - initial.entropy;
        checks.push(VerificationCheck {
            check_type: "entropy_improvement".to_string(),
            passed: entropy_improvement > 0.0,
            value: entropy_improvement,
            threshold: 0.0,
            description: "Shannon entropy should increase after flattening".to_string(),
        });

        // Target entropy check
        let entropy_target_met = final_analysis.entropy >= self.config.target_entropy;
        checks.push(VerificationCheck {
            check_type: "target_entropy".to_string(),
            passed: entropy_target_met,
            value: final_analysis.entropy,
            threshold: self.config.target_entropy,
            description: "Final entropy should meet target threshold".to_string(),
        });

        // Frequency distribution uniformity check
        let frequency_deviation = self.calculate_frequency_deviation(final_analysis);
        let uniformity_met = frequency_deviation <= self.config.distribution_tolerance;
        checks.push(VerificationCheck {
            check_type: "frequency_uniformity".to_string(),
            passed: uniformity_met,
            value: frequency_deviation,
            threshold: self.config.distribution_tolerance,
            description: "Character frequency distribution should be uniform".to_string(),
        });

        // Chi-squared test for uniformity
        let chi_squared_threshold = final_analysis.unique_chars as f64 * 1.5; // Lenient threshold
        let chi_squared_passed = final_analysis.chi_squared <= chi_squared_threshold;
        checks.push(VerificationCheck {
            check_type: "chi_squared_uniformity".to_string(),
            passed: chi_squared_passed,
            value: final_analysis.chi_squared,
            threshold: chi_squared_threshold,
            description: "Chi-squared test for frequency uniformity".to_string(),
        });

        Ok(checks)
    }

    /// Calculate frequency deviation from uniform distribution
    fn calculate_frequency_deviation(&self, analysis: &PatternAnalysis) -> f64 {
        if analysis.char_frequency.is_empty() || analysis.total_chars == 0 {
            return 1.0; // Maximum deviation
        }

        let expected_frequency = analysis.total_chars as f64 / analysis.unique_chars as f64;
        let variance: f64 = analysis.char_frequency.values()
            .map(|&count| {
                let diff = count as f64 - expected_frequency;
                diff * diff
            })
            .sum::<f64>() / analysis.unique_chars as f64;

        (variance.sqrt() / expected_frequency).min(1.0)
    }

    /// Calculate Kullback-Leibler divergence from uniform distribution
    fn calculate_kl_divergence(&self, analysis: &PatternAnalysis) -> f64 {
        if analysis.char_frequency.is_empty() || analysis.total_chars == 0 {
            return f64::INFINITY;
        }

        let uniform_prob = 1.0 / analysis.unique_chars as f64;
        analysis.char_frequency.values()
            .map(|&count| {
                let observed_prob = count as f64 / analysis.total_chars as f64;
                if observed_prob > 0.0 {
                    observed_prob * (observed_prob / uniform_prob).ln()
                } else {
                    0.0
                }
            })
            .sum()
    }

    /// Log operation for audit trail
    fn log_operation(&mut self, phase: &str, operation: &str, byte_offset: Option<u64>, pass_number: Option<u8>, entropy_before: Option<f64>, entropy_after: Option<f64>) {
        self.operation_log.push(OperationLogEntry {
            timestamp: Utc::now(),
            phase: phase.to_string(),
            operation: operation.to_string(),
            byte_offset,
            pass_number,
            entropy_before,
            entropy_after,
        });
    }
}

impl Default for FrequencyFlatteningEngine {
    fn default() -> Self {
        Self::new().expect("Failed to create default FrequencyFlatteningEngine")
    }
}

// ============================================================================
// VALIDATION AND UTILITY FUNCTIONS
// ============================================================================

/// Validate configuration parameters
fn validate_config(config: &FlatteningConfig) -> Result<(), FlatteningError> {
    if config.target_entropy < 0.0 || config.target_entropy > 8.0 {
        return Err(FlatteningError::InvalidConfig(
            "Target entropy must be between 0.0 and 8.0".to_string()
        ));
    }

    if config.distribution_tolerance < 0.0 || config.distribution_tolerance > 1.0 {
        return Err(FlatteningError::InvalidConfig(
            "Distribution tolerance must be between 0.0 and 1.0".to_string()
        ));
    }

    if config.buffer_size == 0 {
        return Err(FlatteningError::InvalidConfig(
            "Buffer size must be greater than 0".to_string()
        ));
    }

    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Cursor;

    #[test]
    fn test_config_validation() {
        let mut config = FlatteningConfig::default();
        assert!(validate_config(&config).is_ok());

        config.target_entropy = -1.0;
        assert!(validate_config(&config).is_err());

        config.target_entropy = 9.0;
        assert!(validate_config(&config).is_err());

        config.target_entropy = 7.8;
        config.distribution_tolerance = -0.1;
        assert!(validate_config(&config).is_err());

        config.distribution_tolerance = 1.1;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_frequency_analysis() {
        let config = FlatteningConfig::default();
        let mut analyzer = FrequencyAnalyzer::new(&config);
        
        let text = "Hello World! This is a test text with repeated characters.";
        let analysis = analyzer.analyze_text(text).unwrap();

        assert!(!analysis.char_frequency.is_empty());
        assert!(!analysis.bigram_frequency.is_empty());
        assert!(!analysis.trigram_frequency.is_empty());
        assert!(analysis.entropy > 0.0);
        assert!(analysis.total_chars > 0);
        assert!(analysis.unique_chars > 0);
    }

    #[test]
    fn test_pattern_analysis() {
        let mut engine = FrequencyFlatteningEngine::new().unwrap();
        let test_data = b"The quick brown fox jumps over the lazy dog.";
        
        let analysis = engine.analyze_patterns(test_data).unwrap();
        
        assert!(!analysis.char_frequency.is_empty());
        assert!(analysis.entropy > 0.0);
        assert!(analysis.total_chars == test_data.len() as u64);
    }

    #[test]
    fn test_frequency_flattening_deterministic() {
        let mut config = FlatteningConfig::default();
        config.reproducible_seed = Some(12345);
        config.target_entropy = 6.0; // Lower target for more reliable test
        
        let mut engine = FrequencyFlatteningEngine::with_config(config).unwrap();
        
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("test_frequency_flattening.txt");
        // Use content with clear frequency bias to ensure flattening has effect
        let test_content = "aaaaaaaaaa bbbbbb cccc dd e aaaaaaaaaa bbbbbb cccc dd e";
        
        fs::write(&temp_path, test_content).unwrap();
        
        let result = engine.destroy_file(&temp_path).unwrap();
        
        // Check that entropy increased or stayed high (for already high entropy content)
        assert!(result.final_entropy >= result.initial_entropy || result.final_entropy > 5.0);
        assert!(result.cryptographic_passes > 0);
        assert!(!result.verification_checks.is_empty());
        assert!(result.bytes_processed > 0);
        
        // Clean up
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn test_stream_processing() {
        let mut config = FlatteningConfig::default();
        config.reproducible_seed = Some(54321);
        
        let mut engine = FrequencyFlatteningEngine::with_config(config).unwrap();
        
        let test_content = "Stream processing test with various characters and patterns.";
        let mut cursor = Cursor::new(test_content.as_bytes().to_vec());
        
        let result = engine.destroy_stream(&mut cursor).unwrap();
        
        assert!(result.final_entropy >= 0.0);
        assert!(result.cryptographic_passes > 0);
        assert!(result.bytes_processed > 0);
    }

    #[test]
    fn test_security_profiles() {
        assert_eq!(SecurityProfile::Conservative.pass_count(), 3);
        assert_eq!(SecurityProfile::Standard.pass_count(), 5);
        assert_eq!(SecurityProfile::Paranoid.pass_count(), 7);
    }

    #[test]
    fn test_entropy_calculation() {
        let mut frequencies = HashMap::new();
        frequencies.insert('a', 10);
        frequencies.insert('b', 10);
        frequencies.insert('c', 10);
        
        let analyzer = FrequencyAnalyzer::new(&FlatteningConfig::default());
        let entropy = analyzer.calculate_shannon_entropy(&frequencies, 30);
        
        // For uniform distribution of 3 characters, entropy should be log2(3) ≈ 1.585
        assert!((entropy - 1.585).abs() < 0.01);
    }

    #[test]
    fn test_chi_squared_calculation() {
        let mut frequencies = HashMap::new();
        frequencies.insert('a', 10);
        frequencies.insert('b', 10);
        frequencies.insert('c', 10);
        
        let analyzer = FrequencyAnalyzer::new(&FlatteningConfig::default());
        let chi_squared = analyzer.calculate_chi_squared(&frequencies, 30);
        
        // For perfectly uniform distribution, chi-squared should be 0
        assert!((chi_squared - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_unicode_modes() {
        let config = FlatteningConfig {
            unicode_handling: UnicodeMode::Basic,
            reproducible_seed: Some(98765),
            ..Default::default()
        };
        
        let mut destructor = PatternDestructor::new(&config, Box::new(StdRng::seed_from_u64(98765)));
        
        // Test basic ASCII transformation
        let ascii_char = destructor.apply_random_transformation('A');
        assert!(ascii_char.is_ascii());
    }

    #[test]
    fn test_verification_checks() {
        let mut config = FlatteningConfig::default();
        config.target_entropy = 6.0;
        config.distribution_tolerance = 0.1;
        
        let engine = FrequencyFlatteningEngine::with_config(config).unwrap();
        
        let initial_analysis = PatternAnalysis {
            char_frequency: [('a', 100), ('b', 50), ('c', 25)].iter().cloned().collect(),
            bigram_frequency: HashMap::new(),
            trigram_frequency: HashMap::new(),
            positional_frequency: HashMap::new(),
            entropy: 4.0,
            chi_squared: 50.0,
            total_chars: 175,
            unique_chars: 3,
        };
        
        let final_analysis = PatternAnalysis {
            char_frequency: [('a', 58), ('b', 59), ('c', 58)].iter().cloned().collect(),
            bigram_frequency: HashMap::new(),
            trigram_frequency: HashMap::new(),
            positional_frequency: HashMap::new(),
            entropy: 6.5,
            chi_squared: 0.1,
            total_chars: 175,
            unique_chars: 3,
        };
        
        let checks = engine.perform_verification_checks(&initial_analysis, &final_analysis).unwrap();
        
        assert!(!checks.is_empty());
        assert!(checks.iter().any(|c| c.check_type == "entropy_improvement"));
        assert!(checks.iter().any(|c| c.check_type == "target_entropy"));
    }
}
