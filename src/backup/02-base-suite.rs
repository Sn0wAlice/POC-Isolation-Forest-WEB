use rand::distributions::Uniform;
use rand::Rng;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Write, Read};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum AttackType {
    None,
    PathTraversal,
    XSS,
    PathTraversalAndXSS,
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

    fn train(&mut self, _data: &[(String, AttackType)]) {
        // Placeholder for training the Isolation Forest
        // You can implement the training logic here
    }

    fn score(&self, _url: &str) -> f64 {
        // Placeholder for scoring a URL using the Isolation Forest
        // Return a random score for demonstration purposes
        rand::thread_rng().gen_range(0.0..1.0)
    }

    fn save_to_file(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = serde_json::to_string(self)?;
        let mut file = File::create(filename)?;
        file.write_all(serialized.as_bytes())?;
        Ok(())
    }

    fn load_from_file(filename: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = File::open(filename)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let model: IsolationForest = serde_json::from_str(&contents)?;
        Ok(model)
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


fn main() {
    // Generate fake data with 1000 normal URLs, 50 path traversal attacks, and 50 XSS attacks
    let data = generate_fake_data(1000, 50, 50);

    // Train Isolation Forest
    let mut forest = IsolationForest::new();
    forest.train(&data);

    // Save the trained model to a file
    if let Err(err) = forest.save_to_file("isolation_forest_model.json") {
        eprintln!("Error saving model: {}", err);
        return;
    }

    // Load the trained model from the file
    let loaded_forest = match IsolationForest::load_from_file("isolation_forest_model.json") {
        Ok(model) => model,
        Err(err) => {
            eprintln!("Error loading model: {}", err);
            return;
        }
    };

    // Score URLs using the loaded model
    for (url, attack_type) in &data {
        let score = loaded_forest.score(url);
        // Assuming a higher score indicates a higher likelihood of being an attack
        let is_attack = score > 0.5;
        let predicted_attack_type = if is_attack {
            "Attack"
        } else {
            "Normal"
        };
        //println!("URL: {}, Predicted: {}, Actual: {:?}", url, predicted_attack_type, attack_type);
    }

}
