use rand::distributions::Uniform;
use extended_isolation_forest::{Forest, ForestOptions};
use rand::Rng;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Copy)]
enum AttackType {
    None,
    PathTraversal,
    XSS,
    PathTraversalAndXSS
}

#[derive(Debug, Serialize, Deserialize)]
struct IsolationForest {
    // Placeholder for Isolation Forest data structure
    // You can include fields representing the trained model here
}

impl IsolationForest {
    fn new() -> Self {
        // Initialize Isolation Forest
        IsolationForest {}
    }


    fn train(&mut self, data: &[(String, AttackType)], filename: &str) {
        println!("Training the Isolation Forest with {} samples...", data.len());
        
        // Define patterns for path traversal and XSS attacks
        let path_traversal_patterns = vec!["../", "..\\", "/../", "\\..\\"];
        let xss_patterns = vec!["<script>", "</script>", "javascript:", "alert("];

        // Prepare vector to store serialized training data
        let mut serialized_data = Vec::new();

        // Iterate through the data samples
        for (url, attack_type) in data {
            // Check for path traversal attack
            let is_path_traversal = path_traversal_patterns.iter().any(|pattern| url.contains(pattern));

            // Check for XSS attack
            let is_xss = xss_patterns.iter().any(|pattern| url.contains(pattern));

            // Determine the attack type based on detection
            let detected_attack_type = match (is_path_traversal, is_xss) {
                (true, true) => AttackType::PathTraversalAndXSS,
                (true, false) => AttackType::PathTraversal,
                (false, true) => AttackType::XSS,
                _ => AttackType::None,
            };

            // Store the URL, attack type, and detected attack type in a JSON object
            let json_obj = serde_json::json!({
                "url": url,
                "attack_type": attack_type,
                "detected_attack_type": detected_attack_type,
            });

            // Serialize the JSON object and push it to the vector
            let serialized_obj = serde_json::to_string(&json_obj).expect("Failed to serialize JSON object");
            serialized_data.push(serialized_obj);
        }

        // Write the serialized training data to the file
        let mut file = File::create(filename).expect("Failed to create file");
        for serialized_obj in serialized_data {
            file.write_all(serialized_obj.as_bytes()).expect("Failed to write to file");
            file.write_all(b"\n").expect("Failed to write to file");
        }

        println!("Training data saved to file: {}", filename);
    }


    fn score(&self, _url: &str) -> f64 {
        // Placeholder for scoring a URL using the Isolation Forest
        // Return a random score for demonstration purposes
        rand::thread_rng().gen_range(0.0..1.0)
    }

    fn save_to_file<T: Serialize>(&self, fname: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("{:?}", self);
        let list_as_json = serde_json::to_string(self)?;
        let mut file = File::create(fname)?;
        file.write_all(list_as_json.as_bytes())?;
        Ok(())
    }

    fn load_from_file(filename: &str) -> Vec<(String, AttackType, AttackType)> {
        let mut training_data = Vec::new();
        let file = File::open(filename).expect("Failed to open file");
        let reader = BufReader::new(file);
    
        for line in reader.lines() {
            let line = line.expect("Failed to read line from file");
            let json_obj: serde_json::Value = serde_json::from_str(&line).expect("Failed to parse JSON");
            
            // Extract URL, attack type, and detected attack type from JSON object
            let url = json_obj["url"].as_str().expect("Invalid JSON format").to_string();
            let attack_type = serde_json::from_value(json_obj["attack_type"].clone()).expect("Failed to deserialize attack type");
            let detected_attack_type = serde_json::from_value(json_obj["detected_attack_type"].clone()).expect("Failed to deserialize detected attack type");
            
            training_data.push((url, attack_type, detected_attack_type));
        }
    
        training_data
    }
}

fn generate_fake_data(n_normal: usize, n_path_traversal: usize, n_xss: usize) -> Vec<(String, AttackType)> {
    let mut data = Vec::new();
    let normal_urls = generate_normal_urls(n_normal);
    let path_traversal_urls = generate_path_traversal_urls(n_path_traversal);
    let xss_urls = generate_xss_urls(n_xss);
    
    for url in normal_urls {
        data.push((url, AttackType::None));
    }
    for url in path_traversal_urls {
        data.push((url, AttackType::PathTraversal));
    }
    for url in xss_urls {
        data.push((url, AttackType::XSS));
    }

    // Add some URLs that are both path traversal and XSS attacks
    for _ in 0..(n_path_traversal.min(n_xss)) {
        let url = generate_path_traversal_and_xss_url();
        data.push((url, AttackType::PathTraversalAndXSS));
    }

    data
}

fn generate_normal_urls(n: usize) -> Vec<String> {
    let mut urls = Vec::new();
    let valid_chars: HashSet<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./".chars().collect();
    let mut rng = rand::thread_rng();
    for _ in 0..n {
        let url_len = rng.gen_range(5..15); // Generate URLs with length between 5 and 15 characters
        let url: String = (0..url_len)
            .map(|_| *valid_chars.iter().nth(rng.gen_range(0..valid_chars.len())).unwrap())
            .collect();
        urls.push(url);
    }
    urls
}

fn generate_path_traversal_urls(n: usize) -> Vec<String> {
    // For simplicity, generating path traversal attack URLs randomly
    let mut urls = Vec::new();
    let traversal_strings = vec!["../../etc/passwd", "../../../etc/shadow", "../../../../../../../etc/passwd"];
    let mut rng = rand::thread_rng();
    for _ in 0..n {
        let traversal_idx = rng.gen_range(0..traversal_strings.len());
        urls.push(traversal_strings[traversal_idx].to_string());
    }
    urls
}

fn generate_xss_urls(n: usize) -> Vec<String> {
    // For simplicity, generating XSS attack URLs randomly
    let mut urls = Vec::new();
    let xss_strings = vec!["<script>alert('XSS attack');</script>", "<img src=\"javascript:alert('XSS');\">"];
    let mut rng = rand::thread_rng();
    for _ in 0..n {
        let xss_idx = rng.gen_range(0..xss_strings.len());
        urls.push(xss_strings[xss_idx].to_string());
    }
    urls
}

fn generate_path_traversal_and_xss_url() -> String {
    // For simplicity, generating a path traversal and XSS attack URL
    "../../../../../etc/passwd<script>alert('XSS');</script>".to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <command>", args[0]);
        println!("Commands:");
        println!("  --train: Train the model and save it");
        println!("  --check: Load the model, generate random URLs and try to detect attacks");
        return;
    }

    match args[1].as_str() {
        "--train" => {
            // Generate fake data with 1000 normal URLs, 50 path traversal attacks, and 50 XSS attacks
            let data = generate_fake_data(1000, 50, 50);

            // Train Isolation Forest
            let mut forest = IsolationForest::new();
            forest.train(&data, "isolation_forest_model.json");

            println!("Model trained and saved successfully.");
        }
        "--check" => {
            // Load the trained model from the file
            let loaded_forest: Vec<(String, AttackType, AttackType)> = IsolationForest::load_from_file("isolation_forest_model.json");

            // Generate random URLs and try to detect attacks
            println!("Url, Attack or not ?");
            for _ in 0..100 {
                let url = generate_random_url(true);
                let is_attack = detect_attack(&loaded_forest, &url);
                let predicted_attack_type = if is_attack {
                    "Attack"
                } else {
                    "Normal"
                };
                println!("url: {}, {}", url, predicted_attack_type);
            }
        }
        _ => {
            println!("Invalid command. Use --train or --check.");
        }
    }
}


fn detect_attack(data: &[(String, AttackType, AttackType)], url: &str) -> bool {
    // Convert the data to feature vectors
    let feature_vectors: Vec<_> = data.iter().map(|(url, _, _)| extract_features(url)).collect();

    // Determine the number of dimensions in the feature vectors
    let num_dimensions = feature_vectors[0].len(); // Assuming all feature vectors have the same length

    // Ensure extension level doesn't exceed dimensions
    let extension_level = num_dimensions.min(10); // Set a reasonable limit for the extension level

    // Train Isolation Forest
    let options = ForestOptions {
        n_trees: 150,
        sample_size: 200,
        max_tree_depth: None,
        extension_level: extension_level-1,
    };
    let forest = Forest::from_slice(&feature_vectors, &options).expect("Failed to create Isolation Forest");

    // Compute anomaly score for the URL
    let score = forest.score(&extract_features(url));

    // Define a threshold for classifying URLs as attacks
    let threshold = 0.5;

    // If the score exceeds the threshold, classify it as an attack
    score > threshold
}


fn extract_features(url: &str) -> [f64; 6] {
    // Extract more relevant features from the URL
    let url_size = url.len() as f64; // Size of the URL
    let num_slashes = url.chars().filter(|&c| c == '/').count() as f64; // Number of slashes in the URL
    let num_dots = url.chars().filter(|&c| c == '.').count() as f64; // Number of dots in the URL
    let num_open_angle_brackets = url.matches('<').count() as f64; // Number of '<' characters in the URL
    let num_close_angle_brackets = url.matches('>').count() as f64; // Number of '>' characters in the URL
    let num_javascript_keywords = vec!["javascript", "script", "alert", "prompt", "confirm"]
        .into_iter()
        .map(|keyword| url.to_lowercase().matches(keyword).count())
        .sum::<usize>() as f64; // Number of JavaScript keywords in the URL

    // Return the extracted features as an array
    [url_size, num_slashes, num_dots, num_open_angle_brackets, num_close_angle_brackets, num_javascript_keywords]
}






fn generate_random_url(include_threat: bool) -> String {
    let valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789---._./";
    let mut rng = rand::thread_rng();
    let url_len = rng.gen_range(5..15); // Generate URLs with length between 5 and 15 characters
    let mut url: String = (0..url_len)
        .map(|_| valid_chars.chars().nth(rng.gen_range(0..valid_chars.len())).unwrap())
        .collect();

    if include_threat && rng.gen_bool(0.5) {
        // Randomly include a threat (path traversal or XSS) in the URL
        let threat_type = rng.gen_range(0..2); // 0 for path traversal, 1 for XSS
        match threat_type {
            0 => {
                let traversal_strings = vec!["../", "..\\", "/../", "\\..\\"];
                let traversal_idx = rng.gen_range(0..traversal_strings.len());
                let traversal = traversal_strings[traversal_idx];
                url = format!("{}{}", traversal, url);
            }
            1 => {
                let xss_strings = vec!["<script>alert('XSS attack');</script>", "<img src=\"javascript:alert('XSS');\">"];
                let xss_idx = rng.gen_range(0..xss_strings.len());
                let xss = xss_strings[xss_idx];
                url.push_str(&xss);
            }
            _ => {}
        }
    }

    url
}
