use crate::cli::{ObserverWardConfig, UnixSocketAddr};
use crate::helper::Helper;
use crate::output::Output;
use crate::{MatchedResult, ObserverWard, cluster_templates};
use actix_web::{App, HttpResponse, HttpServer, Responder, get, middleware, post, rt, web};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use console::Emoji;
#[cfg(not(target_os = "windows"))]
use daemonize::Daemonize;
use engine::execute::ClusterType;
use futures::StreamExt;
use futures::channel::mpsc::unbounded;
use log::{error, info};
use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::RwLock;

#[derive(Clone, Debug)]
struct TokenAuth {
  token: Option<String>,
}

fn validator(token_auth: web::Data<TokenAuth>, credentials: BearerAuth) -> bool {
  if let Some(token) = &token_auth.token {
    token == credentials.token()
  } else {
    true
  }
}

#[post("/v1/observer_ward")]
async fn what_web_api(
  token: web::Data<TokenAuth>,
  auth: BearerAuth,
  config: web::Json<ObserverWardConfig>,
  cli_config: web::Data<ObserverWardConfig>,
  cl: web::Data<RwLock<ClusterType>>,
) -> impl Responder {
  if !validator(token, auth) {
    return HttpResponse::Unauthorized().finish();
  }
  let mut config = config.clone();
  if config.plugin.is_some(){
    config.plugin = cli_config.plugin.clone();
  }
  config.config_dir = cli_config.config_dir.clone();
  config.mode = cli_config.mode.clone();
  config.proxy = cli_config.proxy.clone();
  config.nuclei_args = cli_config.nuclei_args.clone();
  let webhook = config.webhook.is_some();
  let cl = {
    if let Ok(cl_guard) = cl.read() {
      cl_guard.deref().clone()
    } else {
      ClusterType::default()
    }
  };
  let output = Output::new(&config);
  let (tx, mut rx) = unbounded();
  tokio::task::spawn(async move {
    ObserverWard::new(&config, cl).execute(tx).await;
  });
  if webhook {
    // 异步识别任务，通过webhook返回结果
    rt::spawn(async move {
      while let Some(execute_result) = rx.next().await {
        output.webhook_results(vec![execute_result.matched]).await;
      }
    });
    HttpResponse::Ok().finish()
  } else {
    let mut results: Vec<BTreeMap<String, MatchedResult>> = Vec::new();
    while let Some(execute_result) = rx.next().await {
      results.push(execute_result.matched)
    }
    HttpResponse::Ok().json(results)
  }
}

#[post("/v1/config")]
async fn set_config_api(
  token: web::Data<TokenAuth>,
  auth: BearerAuth,
  config: web::Json<ObserverWardConfig>,
  cl: web::Data<RwLock<ClusterType>>,
  cli_config: web::Data<ObserverWardConfig>,
) -> impl Responder {
  if !validator(token, auth) {
    return HttpResponse::Unauthorized().finish();
  }
  // 创建一个可修改的副本，并继承服务端的配置目录等字段
  let mut cfg = config.clone();
  // 如果用户提交了 plugin 路径为 "default"，沿用服务器端配置
  if cfg.plugin.is_some() {
      cfg.plugin = cli_config.plugin.clone();
  }
  cfg.config_dir = cli_config.config_dir.clone();
  cfg.mode = cli_config.mode.clone();
  cfg.proxy = cli_config.proxy.clone();
  cfg.nuclei_args = cli_config.nuclei_args.clone();
  let helper = Helper::new(&cfg);
  if cfg.update_fingerprint {
      helper.update_fingerprint().await;
  }
  if cfg.update_service_fingerprint {
      helper.update_service_fingerprint().await;
  }
  if cfg.update_plugin {
      helper.update_plugins().await;
  }
  // 重新加载模板，更新聚类
  if let Ok(mut cl_guard) = cl.write() {
      let templates = cfg.templates();
      let new_cl = cluster_templates(&templates);
      *cl_guard = new_cl;
  }
  HttpResponse::Ok().json(cfg)
}

#[get("/v1/config")]
async fn get_config_api(
  token: web::Data<TokenAuth>,
  auth: BearerAuth,
  config: web::Data<ObserverWardConfig>,
) -> impl Responder {
  if !validator(token, auth) {
    return HttpResponse::Unauthorized().finish();
  }
  HttpResponse::Ok().json(config.clone())
}

pub async fn api_server(
  listening_address: &UnixSocketAddr,
  config: ObserverWardConfig,
) -> std::io::Result<()> {
  let templates = config.templates();
  info!("{}probes loaded: {}", Emoji("📇", ""), templates.len());
  let cl = cluster_templates(&templates);
  info!("{}optimized probes: {}", Emoji("🚀", ""), cl.count());
  let cluster_templates = web::Data::new(RwLock::new(cl));
  let web_config = web::Data::new(config.clone());
  let token_auth = web::Data::new(TokenAuth {
    token: config.token.clone(),
  });
  let token = config.token.clone();
  let http_server = HttpServer::new(move || {
    App::new()
      .wrap(middleware::Logger::default())
      .app_data(token_auth.clone())
      .app_data(web_config.clone())
      .app_data(web::JsonConfig::default().limit(40960))
      .app_data(cluster_templates.clone())
      .service(what_web_api)
      .service(get_config_api)
      .service(set_config_api)
  });
  let (http_server, url) = match &listening_address {
    #[cfg(unix)]
    UnixSocketAddr::Unix(u) => (
      http_server.bind_uds(u)?,
      "http://localhost/v1/observer_ward".to_string(),
    ),
    UnixSocketAddr::SocketAddr(sa) => (
      http_server.bind(sa)?,
      format!("http://{listening_address}/v1/observer_ward"),
    ),
  };
  print_help(&url, token, listening_address);
  http_server.workers(config.thread).run().await
}

fn print_help(url: &str, t: Option<String>, listening_address: &UnixSocketAddr) {
  let api_doc = match listening_address {
    #[cfg(unix)]
    UnixSocketAddr::Unix(p) => {
      info!(
        "{}API service has been started: {}",
        Emoji("🌐", ""),
        p.to_string_lossy()
      );
      format!(
        r#"curl --request POST \
--unix-socket {} \
--url {} \
--header 'Authorization: Bearer {}' \
--json '{{"target":["https://httpbin.org/"]}}'"#,
        listening_address,
        url,
        t.unwrap_or_default()
      )
    }
    UnixSocketAddr::SocketAddr(_) => {
      info!("{}API service has been started: {}", Emoji("🌐", ""), url);
      format!(
        r#"curl --request POST \
--url {} \
--header 'Authorization: Bearer {}' \
--json '{{"target":["https://httpbin.org/"]}}'"#,
        url,
        t.unwrap_or_default()
      )
    }
  };
  let result = r#"[result...]"#;
  info!("{}:{}", Emoji("📔", ""), api_doc);
  info!("{}:{}", Emoji("🗳", ""), result);
}

#[cfg(not(target_os = "windows"))]
pub fn background() {
  let stdout = std::fs::File::create("/tmp/observer_ward.out").unwrap();
  let stderr = std::fs::File::create("/tmp/observer_ward.err").unwrap();

  let daemonize = Daemonize::new()
    .pid_file("/tmp/observer_ward.pid") // Every method except `new` and `start`
    .chown_pid_file(false) // is optional, see `Daemonize` documentation
    .working_directory("/tmp") // for default behaviour.
    .user("nobody")
    .group("daemon") // Group name
    .umask(0o777) // Set umask, `0o027` by default.
    .stdout(stdout) // Redirect stdout to `/tmp/observer_ward.out`.
    .stderr(stderr) // Redirect stderr to `/tmp/observer_ward.err`.
    .privileged_action(|| "Executed before drop privileges");
  match daemonize.start() {
    Ok(_) => info!("{}Success, daemonized", Emoji("ℹ️", "")),
    Err(e) => error!("{}Error, {}", Emoji("💢", ""), e),
  }
}

#[cfg(target_os = "windows")]
pub fn background() {
  error!(
    "{}Windows does not support background services",
    Emoji("💢", "")
  );
}
