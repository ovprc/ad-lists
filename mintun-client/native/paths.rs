use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct Paths {
    pub root: PathBuf,
    pub state_file: PathBuf,
    pub cores: PathBuf,
    pub cache: PathBuf,
    pub updates: PathBuf,
}

impl Paths {
    pub fn new(override_root: Option<PathBuf>) -> Result<Self> {
        let root = match override_root {
            Some(path) => path,
            None => default_root()?,
        };
        std::fs::create_dir_all(&root).context("Не удалось создать папку данных MinTun")?;
        let root = root.canonicalize().context("Не удалось определить папку данных")?;
        let paths = Self {
            state_file: root.join("state.bin"),
            cores: root.join("cores"),
            cache: root.join("runtime").join("cache.db"),
            updates: root.join("updates"),
            root,
        };
        for directory in [&paths.root, &paths.cores, paths.cache.parent().unwrap(), &paths.updates] {
            std::fs::create_dir_all(directory)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(paths)
    }

    pub fn owns_core(&self, path: &Path) -> bool {
        let Ok(path) = path.canonicalize() else { return false };
        let Ok(root) = self.cores.canonicalize() else { return false };
        path != root && path.starts_with(root)
    }

    pub fn bundled_core(&self) -> Result<PathBuf> {
        #[cfg(target_os = "android")]
        {
            let path = self.cores.join("embedded");
            std::fs::create_dir_all(&path)?;
            Ok(path)
        }
        #[cfg(not(target_os = "android"))]
        {
            let executable = std::env::current_exe()?;
            let parent = executable.parent().context("Не найден каталог приложения")?;
            let directory = parent.join("core");
            ensure!(directory.is_dir(), "Ядро не найдено. Распакуйте весь пакет MinTun вместе с папкой core.");
            Ok(directory)
        }
    }
}

fn default_root() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        Ok(PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA не определён")?).join("MinTunClient"))
    }
    #[cfg(target_os = "linux")]
    {
        let base = match std::env::var_os("XDG_DATA_HOME").filter(|s| !s.is_empty()) {
            Some(path) => {
                let path = PathBuf::from(path);
                ensure!(path.is_absolute(), "XDG_DATA_HOME должен быть абсолютным путём");
                path
            }
            None => PathBuf::from(std::env::var_os("HOME").context("HOME не определён")?).join(".local/share"),
        };
        Ok(base.join("MinTunClient"))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(PathBuf::from(std::env::var_os("HOME").context("HOME не определён")?)
            .join("Library/Application Support/MinTunClient"))
    }
    #[cfg(target_os = "android")]
    {
        Ok(crate::android::data_directory()?.join("MinTunClient"))
    }
}
