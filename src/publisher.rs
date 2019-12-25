use crossbeam_channel::Receiver;
use futures::compat::Future01CompatExt;
use hubcaps::comments::CommentOptions;
use hubcaps::{Error, Github};
use log::*;
use url::Url;

use crate::remote::Log;
use crate::worker::{Report, ReportContent, TestError, TestOutput, TestTarget};

pub struct Publisher {
    github: Github,
    public_url: Url,
}

impl Publisher {
    pub fn new(github: Github, public_url: Url) -> Publisher {
        Publisher { github, public_url }
    }

    pub async fn run(self, report_receiver: Receiver<Report>) {
        for report in report_receiver {
            if let Err(e) = self.handle_report(report).await {
                error!("Failed to publish result: {:?}", e)
            }
        }
    }

    pub async fn handle_report(&self, report: Report) -> Result<(), Error> {
        match report.content {
            ReportContent::Pong { issue_id } => {
                // FIXME: This is broken currently; probably some issue with tokio 0.1/0.2 compat
                //        which the compat wrapper doesn't cover; we'll just wait for hubcaps to
                //        upgrade
                self.github
                    .repo(report.repository.user, report.repository.name)
                    .issues()
                    .get(issue_id)
                    .comments()
                    .create(&CommentOptions {
                        body: "pong".to_string(),
                    })
                    .compat()
                    .await
                    .map(|_| ())?;
                Ok(())
            }
            ReportContent::TestResult {
                result,
                test_target,
            } => match test_target {
                TestTarget::PullRequest(id) => {
                    info!("Posting result in {}#{}", report.repository, id);
                    self.github
                        .repo(report.repository.user, report.repository.name)
                        .issues()
                        .get(id)
                        .comments()
                        .create(&CommentOptions {
                            body: self.format_pull_request_comment(result),
                        })
                        .compat()
                        .await
                        .map(|_| ())
                }
                TestTarget::Branch(branch) => {
                    info!(
                        "Test result for branch {} of {}: {}",
                        branch,
                        report.repository,
                        result.is_ok()
                    );
                    if let Err(e) = result {
                        error!("Error: {}", e);
                    }
                    Ok(())
                }
            },
        }
    }

    fn format_pull_request_comment(&self, result: Result<TestOutput, TestError>) -> String {
        match result {
            Ok(test_output) => format!("Test __passed__!\n\n{}", self.format_logs(&test_output)),
            Err(test_error) => format!(
                "Test __failed__!\n\nCause: {}",
                match test_error {
                    TestError::PerformTest {
                        source,
                        test_output,
                    } => {
                        format!("{}\n\n{}", source, self.format_logs(&test_output))
                    }
                    e => e.to_string(),
                }
            ),
        }
    }

    fn format_logs(&self, test_output: &TestOutput) -> String {
        format!(
            "{}\n\n{}\n{}\n{}",
            if let Some(pcap_file) = &test_output.pcap_file {
                format!(
                    "The captured `.pcap` can be downloaded [here]({}).",
                    self.public_url
                        .join("logs/")
                        .unwrap()
                        .join(pcap_file)
                        .map(|url| url.to_string())
                        .unwrap_or_else(|_| "URL error".to_string())
                )
            } else {
                "The test failed before a `.pcap` was captured".to_string()
            },
            format_log("pktgen", &test_output.log_pktgen),
            format_log("fwd", &test_output.log_fwd),
            format_log("pcap", &test_output.log_pcap)
        )
    }
}

// `Log` is currently just a type alias for `Vec` so `&Log` becomes `&Vec` which clippy doesn't like
#[allow(clippy::ptr_arg)]
fn format_log(name: &str, log: &Log) -> String {
    let mut log_content = String::new();
    for (command, output) in log {
        log_content += &format!("$ {}\n{}\n\n", command, output);
    }
    format!(
        "<details><summary>{} logs</summary>\n\n```\n{}\n```\n</details>",
        name,
        log_content.trim()
    )
}
