use anyhow::{Context, Result, anyhow};
use ironyyyy::security;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn main() -> Result<()> {
    let base_dir = PathBuf::from("databases");
    fs::create_dir_all(&base_dir).context("failed to create databases directory")?;
    ensure_sample_account(&base_dir)?;

    let available = collect_user_databases(&base_dir)?;
    if available.is_empty() {
        return Err(anyhow!("no user databases could be loaded"));
    }

    let index = prompt_user_selection(&available)?;
    let user = &available[index];

    let password = prompt_password("Password: ").context("failed to read password")?;
    let key = security::derive_key(&password, user.metadata.uuid.as_bytes())?;

    let db = read_database(&user.path)?;
    let plain = security::decrypt_payload(&db.encrypted, &key)?;
    let mut payload: EncryptedPayload = serde_json::from_slice(&plain)?;
    security::verify_password(&password, &payload.password_hash)?;

    run_project_repl(user, &mut payload, &key, &user.path)
}

fn ensure_sample_account(base_dir: &Path) -> Result<()> {
    let mut entries = fs::read_dir(base_dir)?;
    if entries.next().is_some() {
        return Ok(());
    }

    let uuid = Uuid::new_v4();
    let metadata = Metadata {
        uuid,
        username: "demo".into(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let password = "demo-pass";
    let salt = security::salt_from_uuid(&uuid).map_err(|e| anyhow!("salt creation: {e}"))?;
    let hash = security::hash_password(password, &salt)?;
    let key = security::derive_key(password, uuid.as_bytes())?;

    let payload = EncryptedPayload {
        password_hash: hash,
        data: sample_project_data(),
    };
    let encrypted = security::encrypt_payload(&serde_json::to_vec(&payload)?, &key)?;
    let disk = OnDiskDatabase {
        metadata: metadata.clone(),
        encrypted,
    };
    let path = base_dir.join(format!("{uuid}.json"));
    fs::write(&path, serde_json::to_string_pretty(&disk)?)?;

    println!("Created a sample account with username 'demo' and password 'demo-pass'.");
    Ok(())
}

fn sample_project_data() -> ProjectData {
    let epic_id = Uuid::new_v4();
    let story_id = Uuid::new_v4();
    ProjectData {
        epics: vec![Epic {
            id: epic_id,
            title: "Onboard security team".into(),
            description: "Introduce the security team to the new CLI".into(),
            status: Status::Backlog,
            stories: vec![Story {
                id: story_id,
                title: "Document encryption standards".into(),
                description: "Write down how Argon2 and AES-GCM are used".into(),
                status: Status::Backlog,
                estimate: Some("2d".into()),
            }],
        }],
    }
}

fn collect_user_databases(base: &Path) -> Result<Vec<AvailableUser>> {
    let mut users = Vec::new();
    for entry in fs::read_dir(base)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let disk = read_database(&path)?;
        users.push(AvailableUser {
            metadata: disk.metadata,
            path,
        });
    }
    users.sort_by_key(|user| user.metadata.username.clone());
    Ok(users)
}

fn prompt_user_selection(users: &[AvailableUser]) -> Result<usize> {
    println!("Available accounts:");
    for (idx, user) in users.iter().enumerate() {
        println!(
            "{}. {} (uuid: {}, created: {})",
            idx + 1,
            user.metadata.username,
            user.metadata.uuid,
            user.metadata.created_at,
        );
    }

    loop {
        let input = prompt_line("Enter account number: ")?;
        if let Ok(choice) = input.trim().parse::<usize>() {
            if choice == 0 || choice > users.len() {
                println!("Please select a number between 1 and {}", users.len());
                continue;
            }
            return Ok(choice - 1);
        }
        println!("Invalid input, try again.");
    }
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    Ok(buffer.trim().to_string())
}

fn read_database(path: &Path) -> Result<OnDiskDatabase> {
    let contents = fs::read_to_string(path)?;
    let disk: OnDiskDatabase = serde_json::from_str(&contents)?;
    Ok(disk)
}

fn run_project_repl(
    user: &AvailableUser,
    payload: &mut EncryptedPayload,
    key: &[u8; 32],
    path: &Path,
) -> Result<()> {
    println!(
        "Logged in as {}. Type 'help' to see commands.",
        user.metadata.username
    );
    loop {
        let input = prompt_line("> ")?;
        match input.trim().to_lowercase().as_str() {
            "help" => print_help(),
            "list epics" => list_epics(&payload.data),
            "list stories" => {
                if let Err(err) = list_stories(&payload.data) {
                    println!("{err}");
                }
            }
            "add epic" => match add_epic(&mut payload.data) {
                Ok(_) => {
                    persist_payload(path, &user.metadata, payload, key)?;
                }
                Err(err) => println!("Failed to add epic: {err}"),
            },
            "add story" => match add_story(&mut payload.data) {
                Ok(_) => {
                    persist_payload(path, &user.metadata, payload, key)?;
                }
                Err(err) => println!("Failed to add story: {err}"),
            },
            "update story status" => match update_story_status(&mut payload.data) {
                Ok(_) => {
                    persist_payload(path, &user.metadata, payload, key)?;
                }
                Err(err) => println!("Failed to move story: {err}"),
            },
            "status summary" => status_summary(&payload.data),
            "save" => {
                persist_payload(path, &user.metadata, payload, key)?;
                println!("Saved.");
            }
            "exit" | "quit" => {
                persist_payload(path, &user.metadata, payload, key)?;
                break;
            }
            command if command.is_empty() => continue,
            _ => println!("Unknown command. Type 'help' for guidance."),
        }
    }
    Ok(())
}

fn print_help() {
    println!("Available commands:");
    println!("  help               - show this message");
    println!("  list epics         - summarize all epics");
    println!("  list stories       - show stories for a specific epic");
    println!("  add epic           - create a new epic");
    println!("  add story          - add a story to an epic");
    println!("  update story status- change a story's workflow state");
    println!("  status summary     - show counts per status");
    println!("  save               - persist changes now");
    println!("  exit/quit          - save and leave");
}

fn list_epics(data: &ProjectData) {
    if data.epics.is_empty() {
        println!("No epics yet.");
        return;
    }
    for epic in &data.epics {
        println!(
            "{} — {} [{}] ({} stories)",
            epic.id,
            epic.title,
            epic.status,
            epic.stories.len()
        );
    }
}

fn list_stories(data: &ProjectData) -> Result<()> {
    let id = prompt_uuid("Epic ID: ")?;
    if let Some(epic) = data.epics.iter().find(|epic| epic.id == id) {
        if epic.stories.is_empty() {
            println!("Epic '{}' has no stories.", epic.title);
        } else {
            for story in &epic.stories {
                println!(
                    "{} — {} [{}] (estimate: {})",
                    story.id,
                    story.title,
                    story.status,
                    story.estimate.as_deref().unwrap_or("unestimated"),
                );
                println!("    {}", story.description);
            }
        }
        Ok(())
    } else {
        Err(anyhow!("epic not found"))
    }
}

fn add_epic(data: &mut ProjectData) -> Result<()> {
    let title = prompt_line("Epic title: ")?;
    let description = prompt_line("Description: ")?;
    let status = prompt_status(Status::Backlog)?;
    let epic = Epic {
        id: Uuid::new_v4(),
        title,
        description,
        status,
        stories: Vec::new(),
    };
    data.epics.push(epic);
    println!("Epic created.");
    Ok(())
}

fn add_story(data: &mut ProjectData) -> Result<()> {
    let epic_id = prompt_uuid("Epic ID to append story: ")?;
    let epic = data
        .epics
        .iter_mut()
        .find(|epic| epic.id == epic_id)
        .ok_or_else(|| anyhow!("epic not found"))?;

    let title = prompt_line("Story title: ")?;
    let description = prompt_line("Story description: ")?;
    let status = prompt_status(Status::Backlog)?;
    let estimate = prompt_line("Estimate (optional): ")?;
    let story = Story {
        id: Uuid::new_v4(),
        title,
        description,
        status,
        estimate: (!estimate.is_empty()).then(|| estimate),
    };
    epic.stories.push(story);
    println!("Story added to epic '{}'.", epic.title);
    Ok(())
}

fn update_story_status(data: &mut ProjectData) -> Result<()> {
    let epic_id = prompt_uuid("Epic ID: ")?;
    let story_id = prompt_uuid("Story ID: ")?;
    let new_status = prompt_status(Status::Backlog)?;

    if let Some(epic) = data.epics.iter_mut().find(|epic| epic.id == epic_id) {
        if let Some(story) = epic.stories.iter_mut().find(|story| story.id == story_id) {
            story.status = new_status;
            println!("Story '{}' moved to {}.", story.title, story.status);
            return Ok(());
        }
    }
    Err(anyhow!("story or epic not found"))
}

fn status_summary(data: &ProjectData) {
    for status in Status::variants() {
        let epic_count = data
            .epics
            .iter()
            .filter(|epic| epic.status == *status)
            .count();
        println!("{} epics in {}", epic_count, status);
    }
}

fn persist_payload(
    path: &Path,
    metadata: &Metadata,
    payload: &EncryptedPayload,
    key: &[u8; 32],
) -> Result<()> {
    let serialized = serde_json::to_vec(payload)?;
    let encrypted = security::encrypt_payload(&serialized, key)?;
    let disk = OnDiskDatabase {
        metadata: metadata.clone(),
        encrypted,
    };
    fs::write(path, serde_json::to_string_pretty(&disk)?)?;
    Ok(())
}

fn prompt_uuid(prompt: &str) -> Result<Uuid> {
    let input = prompt_line(prompt)?;
    let uuid = Uuid::from_str(input.trim()).context("invalid UUID")?;
    Ok(uuid)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OnDiskDatabase {
    metadata: Metadata,
    encrypted: security::EncryptedBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Metadata {
    uuid: Uuid,
    username: String,
    created_at: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct EncryptedPayload {
    password_hash: String,
    data: ProjectData,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct ProjectData {
    epics: Vec<Epic>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Epic {
    id: Uuid,
    title: String,
    description: String,
    status: Status,
    stories: Vec<Story>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Story {
    id: Uuid,
    title: String,
    description: String,
    status: Status,
    estimate: Option<String>,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Status {
    Backlog,
    InProgress,
    Done,
}

impl Status {
    const VARIANTS: [Status; 3] = [Status::Backlog, Status::InProgress, Status::Done];

    fn variants() -> &'static [Status] {
        &Self::VARIANTS
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Status::Backlog => "backlog",
            Status::InProgress => "in-progress",
            Status::Done => "done",
        };
        write!(f, "{text}")
    }
}

fn prompt_status(default: Status) -> Result<Status> {
    loop {
        println!(
            "Available statuses: {}",
            Status::variants()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        let input = prompt_line(&format!("Status [{default}]: "))?;
        if input.trim().is_empty() {
            return Ok(default);
        }
        let normalized = input.trim().to_lowercase();
        if let Some(status) = Status::variants()
            .iter()
            .find(|status| status.to_string() == normalized)
        {
            return Ok(*status);
        }
        println!("Unknown status, try again.");
    }
}

#[derive(Clone)]
struct AvailableUser {
    metadata: Metadata,
    path: PathBuf,
}
