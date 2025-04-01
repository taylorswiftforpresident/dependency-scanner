use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::time::sleep;
use std::time::Duration;
use regex::Regex;

#[derive(StructOpt)]
struct Opt {
    #[structopt(parse(from_os_str))]
    workflow_path: PathBuf,
    
    #[structopt(long)]
    strict: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    critical_dependencies: Option<Vec<String>>, // Optional definition of critical dependencies. These require version pinning.
    trusted_owners: Option<HashSet<String>>,    // Trusted GitHub owners/organizations. These do not require version pinning.
}

/// Load configuration from YAML file
fn load_config(config_path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    match fs::read_to_string(config_path) {
        Ok(content) => {
            let config: Config = serde_yaml::from_str(&content)?;
            Ok(config)
        },
        Err(e) => {
            eprintln!("Warning: Could not load config file: {}", e);
            // Return default config if file not found
            Ok(Config {
                critical_dependencies: Some(Vec::new()),
                trusted_owners: Some(HashSet::new()),
            })
        }
    }
}

/// GitHub advisory API response
#[derive(Debug, Serialize, Deserialize)]
struct GitHubAdvisoryResponse {
    items: Vec<GitHubAdvisory>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GitHubAdvisory {
    id: String,
    number: i64,
    title: String,
    state: String,
    labels: Vec<Label>,
    severity: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Label {
    name: String,
}

/// Structure to store parsed action information
#[derive(Debug, Clone)]
struct ActionRef {
    owner: String,
    repo: String,
    version: String,
    is_commit_sha: bool,
}

impl ActionRef {
    fn from_action_string(action: &str) -> Option<Self> {
        // Skip docker actions
        if action.starts_with("docker://") {
            return None;
        }
        
        // Parse action in format: owner/repo@version
        let parts: Vec<&str> = action.split('@').collect();
        if parts.len() != 2 {
            return None;
        }
        
        let repo_parts: Vec<&str> = parts[0].split('/').collect();
        if repo_parts.len() != 2 {
            return None;
        }
        
        // Check if version is a commit SHA (40 hex characters)
        let commit_sha_regex = Regex::new(r"^[0-9a-f]{40}$").unwrap();
        let is_commit_sha = commit_sha_regex.is_match(parts[1]);
        
        Some(ActionRef {
            owner: repo_parts[0].to_string(),
            repo: repo_parts[1].to_string(),
            version: parts[1].to_string(),
            is_commit_sha,
        })
    }
    
    fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    let config = load_config("critical_dependencies.yaml")?;
    
    let client = Client::builder()
        .user_agent("github-action-security-scanner")
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to build HTTP client: {}", e)))?;
        
    let actions = extract_actions_from_workflow(opt.workflow_path.to_str().unwrap())?;

    let mut vulnerable_actions = Vec::new();
    let mut insecure_pinning = Vec::new();

    println!("Scanning {} actions from workflow", actions.len());
    
    for action in &actions {
        println!("Checking {} for vulnerabilities...", action);
        
        // Check dependency pinning
        if !check_dependency_pinning(action, &config, opt.strict) {
            insecure_pinning.push(action.clone());
        }
        
        if let Some(action_ref) = ActionRef::from_action_string(action) {
            // Check if owner is trusted (for supply chain attacks)
            if !is_trusted_owner(&action_ref.owner, &config) {
                println!("⚠️ Warning: Action {} is from non-trusted owner {}", action, action_ref.owner);
                
                // For non-trusted owners, only accept commit SHAs
                if !action_ref.is_commit_sha {
                    println!("❌ Non-trusted action {} should use commit SHA instead of tag/branch", action);
                    insecure_pinning.push(action.clone());
                }
            }
            
            // Check for known vulnerabilities
            match get_github_advisories(&client, &action_ref).await {
                Ok(advisories) if !advisories.is_empty() => {
                    println!("Vulnerability found in {}!", action);
                    for advisory in &advisories {
                        println!("- Advisory ID: {}, Title: {}", advisory.id, advisory.title);
                    }
                    vulnerable_actions.push(action.clone());
                }
                Ok(_) => println!("✅ No known vulnerabilities for {}", action),
                Err(e) => {
                    eprintln!("Failed to check {}: {}", action, e);
                }
            }
        } else {
            println!("Skipping malformed action reference: {}", action);
        }
        
        // Add a small delay to avoid rate limiting
        sleep(Duration::from_millis(100)).await;
    }

    // Create a final report
    if !vulnerable_actions.is_empty() || !insecure_pinning.is_empty() {
        println!("\n⛔ Security scan failed!");
        
        if !vulnerable_actions.is_empty() {
            println!("\nVulnerable actions found:");
            for action in &vulnerable_actions {
                println!("- {}", action);
            }
        }
        
        if !insecure_pinning.is_empty() {
            println!("\nActions with insecure version pinning:");
            for action in &insecure_pinning {
                println!("- {}", action);
            }
        }
        
        std::process::exit(1);
    }

    println!("\n✅ All actions passed security checks!");
    Ok(())
}

/// Check if an owner is in the trusted owners list
fn is_trusted_owner(owner: &str, config: &Config) -> bool {
    config.trusted_owners.as_ref().map_or(false, |owners| owners.contains(owner))
}

fn extract_actions_from_workflow(workflow_path: &str) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(workflow_path)?;
    let workflow: Value = serde_yaml::from_str(&content)?;

    let mut actions = HashSet::new();
    if let Some(jobs) = workflow.get("jobs").and_then(|v| v.as_mapping()) {
        for job in jobs.values() {
            if let Some(steps) = job.get("steps").and_then(|v| v.as_sequence()) {
                for step in steps {
                    if let Some(action) = step.get("uses").and_then(|v| v.as_str()) {
                        actions.insert(action.to_string());
                    }
                }
            }
        }
    }
    Ok(actions)
}

// Check if a dependency is in the critical_dependencies.yml config
fn check_dependency_pinning(action: &str, config: &Config, strict: bool) -> bool {
    let is_critical = config.critical_dependencies.as_ref().map_or(false, |deps| deps.contains(&action.to_string()));

    // Skip Docker actions for pinning checks
    if action.starts_with("docker://") {
        return true;
    }

    if is_critical {
        if !action.contains('@') {
            println!("❌ Critical dependency {} is not pinned at all!", action);
            return false;
        } else if action.contains("@main") || action.contains("@master") || action.contains("@latest") {
            println!("❌ Critical dependency {} is using an unstable reference!", action);
            return false;
        }
        
        // For critical dependencies, prefer commit SHAs
        if let Some(action_ref) = ActionRef::from_action_string(action) {
            if !action_ref.is_commit_sha {
                println!("⚠️ Critical dependency {} is pinned to a tag, not a commit SHA", action);
                // This is just a warning, not a failure
            }
        }
    } else if strict {
        if !action.contains('@') {
            println!("❌ Dependency {} is not pinned (failing due to --strict)", action);
            return false;
        } else if action.contains("@main") || action.contains("@master") || action.contains("@latest") {
            println!("❌ Dependency {} is using an unstable reference (failing due to --strict)", action);
            return false;
        }
    }

    true
}

/// Query GitHub's advisory database for vulnerabilities in a given GitHub Action
async fn get_github_advisories(client: &Client, action_ref: &ActionRef) -> Result<Vec<GitHubAdvisory>, std::io::Error> {
    let url = format!(
        "https://api.github.com/search/issues?q=repo:github/advisory-database+is:issue+is:open+label:{}/{}",
        action_ref.owner, action_ref.repo
    );
    
    let response = client.get(&url)
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("HTTP request failed: {}", e)))?;

    match response.status() {
        StatusCode::OK => {
            let response_data = response.json::<GitHubAdvisoryResponse>()
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("JSON parsing failed: {}", e)))?;
            Ok(response_data.items)
        },
        
        StatusCode::TOO_MANY_REQUESTS => {
            let retry_after = response
                .headers()
                .get("Retry-After")
                .and_then(|val| val.to_str().ok())
                .and_then(|val| val.parse::<u64>().ok())
                .unwrap_or(60);
                
            println!("Rate limited. Retrying after {} seconds...", retry_after);
            sleep(Duration::from_secs(retry_after)).await;
            
            Box::pin(get_github_advisories(client, action_ref)).await
        },

        status => {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other, 
                format!("Unexpected HTTP status: {}", status)
            ))
        }
    }
}