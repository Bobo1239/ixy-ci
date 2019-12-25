pub mod message;

use actix_web::web::{BytesMut, Data, Payload};
use actix_web::{post, Error, HttpRequest, HttpResponse};
use crossbeam_channel::{Sender, TrySendError};
use futures::compat::Future01CompatExt;
use futures::StreamExt;
use hubcaps::Github;
use log::*;
use ring::digest;
use ring::hmac::{self, VerificationKey};

use crate::config::{self, GitHubConfig};
use crate::worker::Job;
use message::*;

// TODO: Respond with "Sorry dave can't let you do that if @ixy-ci test outside of PR"

#[post("/webhook")]
async fn webhook_service(
    request: HttpRequest,
    mut payload: Payload,
    config: Data<GitHubConfig>,
    github: Data<Github>,
    job_sender: Data<Sender<Job>>,
) -> Result<HttpResponse, Error> {
    let mut body = BytesMut::new();
    while let Some(item) = payload.next().await {
        body.extend_from_slice(&item?);
    }

    let mut response = if let Ok(message) = serde_json::from_slice::<Message>(&body) {
        let repo = message.repository();
        if let Some(webhook_secret) = config.webhook_secrets.get(&repo) {
            if !check_request(&request, &body, &message, webhook_secret) {
                HttpResponse::Unauthorized()
            } else {
                let delivery_id = request
                    .headers()
                    .get("X-GitHub-Delivery")
                    .and_then(|delivery_id| delivery_id.to_str().ok())
                    .unwrap_or("unknown");
                info!("Processing delivery id {}", delivery_id);

                match process_message(
                    message,
                    &config.bot_name,
                    github.get_ref().clone(),
                    job_sender.get_ref().clone(),
                )
                .await
                {
                    Ok(()) => HttpResponse::Ok(),
                    Err(_) => HttpResponse::InternalServerError(),
                }
            }
        } else {
            error!("Failed to find webhook secret for {}", repo);
            HttpResponse::BadRequest()
        }
    } else {
        HttpResponse::BadRequest()
    };

    Ok(response.finish())
}

async fn process_message(
    message: Message,
    bot_name: &str,
    github: Github,
    job_sender: Sender<Job>,
) -> Result<(), Error> {
    let job = match message {
        Message::Ping { .. } => None,
        Message::IssueComment {
            action,
            repository,
            issue,
            comment,
            ..
        } => {
            if action == IssueCommentAction::Created {
                if comment.body.contains(&format!("@{} test", bot_name)) {
                    github
                        .repo(&repository.owner.login, &repository.name)
                        .pulls()
                        .get(issue.number)
                        .get()
                        .compat()
                        .await
                        .map(move |pull| {
                            Some(Job::TestPullRequest {
                                repository: config::Repository {
                                    user: repository.owner.login,
                                    name: repository.name,
                                },
                                fork_user: pull.head.user.login,
                                fork_branch: pull.head.commit_ref,
                                pull_request_id: issue.number,
                            })
                        })
                        .map_err(|e| {
                            error!("Failed to fetch GitHub information to queue test: {:?}", e)
                        })?
                } else if comment.body.contains(&format!("@{} ping", bot_name)) {
                    Some(Job::Ping {
                        repository: config::Repository {
                            user: repository.owner.login,
                            name: repository.name,
                        },
                        issue_id: issue.number,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        }
    };

    if let Some(job) = job {
        info!(
            "Adding new job to queue {:?} (new queue size: {})",
            job,
            job_sender.len() + 1,
        );
        match job_sender.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => error!("Dropping job because queue is full"),
            Err(TrySendError::Disconnected(_)) => panic!("Job queue disconnected"),
        }
    }
    Ok(())
}

// This could be rewritten to a proper middleware but that doesn't really seem worth it atm.
fn check_request(
    request: &HttpRequest,
    payload: &[u8],
    message: &Message,
    github_webhook_secret: &str,
) -> bool {
    let headers = request.headers();

    let event = headers
        .get("X-GitHub-Event")
        .map(|event| event == message.github_event())
        .unwrap_or(false);

    if !event {
        error!("X-GitHub-Event didn't match deserialized message");
    }

    let signature = headers
        .get("X-Hub-Signature") // NOTE: Not X-GitHub-Signature
        .and_then(|signature| hex::decode(&signature.as_bytes()[5..]).ok()) // Skip the "sha1=" prefix
        .map(|signature| {
            // ring verifies the hash in constant time
            let v_key = VerificationKey::new(&digest::SHA1, github_webhook_secret.as_bytes());
            hmac::verify(&v_key, payload, &signature).is_ok()
        })
        .unwrap_or(false);

    if !signature {
        error!("Signature check failed");
    }

    event && signature
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::test::TestRequest;

    #[test]
    fn test_check_request() {
        let payload = br#"
        {
            "zen": "Speak like a human.",
            "hook_id": 1239,
            "repository": {
                "name": "ixy.rs",
                "owner": {
                    "login": "Bobo1239"
                }
            }
        }"#;
        let message = serde_json::from_slice::<Message>(payload).unwrap();
        let request = TestRequest::get()
            .header("X-GitHub-Event", "ping")
            .header(
                "X-Hub-Signature",
                "sha1=b67ff6ab88a9c837a4640348bd5e3b6cb9ba020a",
            )
            .set_payload(payload.as_ref())
            .to_http_request();

        assert!(check_request(&request, payload, &message, "foobar"))
    }
}
