use crate::cli::ObserverWardConfig;
use console::Emoji;
use engine::template::Template;
use log::{error, info, warn};
use std::fs::File;
use std::io::Cursor;
const OBSERVER_WARD_TARGET: &str = env!("OBSERVER_WARD_TARGET");

pub struct Helper<'a> {
  config: &'a ObserverWardConfig,
}

impl<'a> Helper<'a> {
  pub fn new(config: &'a ObserverWardConfig) -> Self {
    Self { config }
  }
  pub async fn update_fingerprint(&self) {
    let fingerprint_path = self.config.config_dir.join("web_fingerprint_v4.json");
    let urls = vec!["https://cns.onedom.com/admin-api/asm/vul-finger-template/export-web-fingerprint-json"];
    for url in urls {
      if let Err(err) = self
        .download_file_from_github(
          url,
          fingerprint_path
            .to_str()
            .unwrap_or("web_fingerprint_v4.json"),
        )
        .await
      {
        error!("{}update fingerprint err: {}", Emoji("💢", ""), err);
        continue;
      } else {
        break;
      };
    }
    if let Ok(f) = File::open(&fingerprint_path) {
      match serde_json::from_reader::<File, Vec<Template>>(f) {
        Ok(ts) => {
          info!(
            "{}successfully updated {} fingerprint",
            Emoji("🔄", ""),
            ts.len()
          );
        }
        Err(err) => {
          error!("{}update fingerprint err: {}", Emoji("💢", ""), err);
          std::fs::remove_file(&fingerprint_path).unwrap_or_default();
          warn!(
            "{}deleted fingerprint file: {:?}",
            Emoji("⚠️", ""),
            fingerprint_path
          );
        }
      }
    }
  }


  /// Download and update service fingerprints
  pub async fn update_service_fingerprint(&self) {
        let service_path = self.config.config_dir.join("service_fingerprint_v4.json");
        // 指向 FingerprintHub 发布的服务指纹文件
        let urls = vec!["https://cns.onedom.com/admin-api/asm/vul-finger-template/export-service-fingerprint-json"];
        for url in urls {
            if let Err(err) = self
                .download_file_from_github(url, service_path.to_str().unwrap_or("service_fingerprint_v4.json"))
                .await
            {
                error!("{}update service fingerprint err: {}", Emoji("", ""), err);
                continue;
            } else {
                break;
            }
        }
        // 与 update_fingerprint 类似的校验逻辑，可选
        if let Ok(f) = File::open(&service_path) {
            match serde_json::from_reader::<File, Vec<Template>>(f) {
                Ok(ts) => {
                    info!("{}successfully updated {} service fingerprint", Emoji("", ""), ts.len());
                }
                Err(err) => {
                    error!("{}update service fingerprint err: {}", Emoji("", ""), err);
                    std::fs::remove_file(&service_path).unwrap_or_default();
                }
            }
        }
    }

  async fn download_file_from_github(
    &self,
    download_url: &str,
    filename: &str,
  ) -> Result<(), std::io::Error> {
    let mut client_builder = self.config.http_client_builder();
    client_builder = client_builder.redirect(engine::slinger::redirect::Policy::Limit(10));
    let client = client_builder.build().unwrap_or_default();
    match client.get(download_url).send().await {
      Ok(response) => match File::create(filename) {
        Ok(mut f) => {
          if !response.status_code().is_success() {
            return Err(std::io::Error::new(
              std::io::ErrorKind::NotFound,
              "NotFound",
            ));
          }
          let mut content = Cursor::new(response.body().clone().unwrap_or_default().to_vec());
          std::io::copy(&mut content, &mut f).unwrap_or_default();
        }
        Err(err) => {
          error!("{}create file: {}", Emoji("💢", ""), err);
          return Err(err);
        }
      },
      Err(err) => {
        error!(
          "{}download from github {}, err: {}",
          Emoji("💢", ""),
          download_url,
          err
        );
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, err));
      }
    }
    Ok(())
  }
  pub async fn update_self(&self) {
    // https://doc.rust-lang.org/reference/conditional-compilation.html
    let mut base_url =
      String::from("https://github.com/emo-crab/observer_ward/releases/download/defaultv4/");
    let mut download_name = OBSERVER_WARD_TARGET.to_string();
    if cfg!(feature = "mcp") {
      download_name.push_str("_mcp");
    }
    if cfg!(target_os = "windows") {
      download_name.push_str(".exe");
    };
    base_url.push_str(&download_name);
    let save_filename = format!("update_{download_name}");
    match self
      .download_file_from_github(&base_url, &save_filename)
      .await
    {
      Ok(_) => {
        info!(
          "{} please rename the file {} => {}",
          Emoji("ℹ️", ""),
          save_filename,
          std::env::current_exe()
            .unwrap_or_default()
            .file_name()
            .unwrap_or(std::ffi::OsStr::new(&download_name))
            .to_string_lossy(),
        );
      }
      Err(err) => {
        error!("{},{}", Emoji("💢", ""), err);
      }
    };
  }
  pub async fn update_plugins(&self) {
    let plugins_zip_path = self.config.config_dir.join("plugins.zip");
    if let Err(err) = self
      .download_file_from_github(
        "https://cns.onedom.com/admin-api/asm/vul/poc-template/plugins-export",
        plugins_zip_path.to_str().unwrap_or("plugins.zip"),
      )
      .await
    {
      error!("{}{}", Emoji("💢", ""), err);
      return;
    };
    let plugins_path = self.config.config_dir.join("plugins");
    if plugins_path.exists() {
      std::fs::remove_dir_all(&plugins_path).unwrap_or_default();
    }
    match File::open(plugins_zip_path) {
      Ok(zf) => {
        match zip::ZipArchive::new(zf) {
          Ok(mut archive) => {
            archive.extract(&self.config.config_dir).unwrap_or_default();
            info!(
              "{}It has been extracted to the {:?}",
              Emoji("ℹ️", ""),
              self.config.config_dir
            );
          }
          Err(err) => {
            error!("{}open zip archive err: {}", Emoji("💢", ""), err);
          }
        };
      }
      Err(err) => {
        error!("{}{}", Emoji("💢", ""), err);
        warn!(
          "{}Please manually unzip the plugins to the directory",
          Emoji("⚠️", "")
        );
      }
    };
  }

  pub async fn run(&self) {
    // 新增：优先检查是否需要更新服务指纹
    if self.config.update_service_fingerprint {
        self.update_service_fingerprint().await;
        std::process::exit(0);
    }
    if self.config.update_fingerprint {
      self.update_fingerprint().await;
      std::process::exit(0);
    }
    if self.config.update_self {
      self.update_self().await;
      std::process::exit(0);
    }
    if self.config.update_plugin {
      self.update_plugins().await;
      std::process::exit(0);
    }
    if let (Some(ts), Some(save_path)) = (&self.config.yaml_probes(), &self.config.probe_path) {
      if let Ok(f) = File::create(save_path) {
        serde_json::to_writer(f, ts).unwrap_or_default();
        info!(
          "{}convert the {} yaml file of the probe directory to a json file {}",
          Emoji("ℹ️", ""),
          ts.len(),
          save_path.to_string_lossy()
        );
      }
      std::process::exit(0);
    }
  }
}
