use rand::distributions::Uniform;
use rand::Rng;
use std::collections::HashSet;

#[derive(Debug, PartialEq)]
enum AttackType {
    None,
    PathTraversal,
    XSS,
    PathTraversalAndXSS,
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
    // Generate fake data with 1000 normal URLs, 50 path traversal attacks, and 50 XSS attacks
    let data = generate_fake_data(1000, 50, 50);

    // Train Isolation Forest
    let forest = train_isolation_forest(&data);

    // Score URLs
    for (url, attack_type) in &data {
        let score = forest.score(url);
        // Assuming a higher score indicates a higher likelihood of being an attack
        let is_attack = score > 0.5;
        let predicted_attack_type = if is_attack {
            "Attack"
        } else {
            "Normal"
        };
        println!("URL: {}, Predicted: {}, Actual: {:?}", url, predicted_attack_type, attack_type);
    }
}

struct IsolationForest {
    // Placeholder for Isolation Forest data structure
}

impl IsolationForest {
    fn new() -> Self {
        // Initialize Isolation Forest
        IsolationForest {}
    }

    fn train(&mut self, _data: &[(String, AttackType)]) {
        // Placeholder for training the Isolation Forest
    }

    fn score(&self, _url: &str) -> f64 {
        // Placeholder for scoring a URL using the Isolation Forest
        // Return a random score for demonstration purposes
        rand::thread_rng().gen_range(0.0..1.0)
    }
}

fn train_isolation_forest(data: &[(String, AttackType)]) -> IsolationForest {
    let mut forest = IsolationForest::new();
    forest.train(data);
    forest
}
