//! Idioma de la interfaz y los mensajes. Inglés por defecto; español, chino,
//! ruso y portugués opcionales. Las cadenas se escriben en el código como
//! `tr("English", "Español")`; para los idiomas extra se busca el literal
//! inglés en un diccionario y, si no está, se cae a inglés (traducción parcial
//! de la superficie más visible, sin tocar los miles de llamadas a tr()).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

static LANG: AtomicU8 = AtomicU8::new(0); // 0 en · 1 es · 2 zh · 3 ru · 4 pt

/// Lista de idiomas disponibles: (código, nombre nativo). El índice = valor LANG.
pub const IDIOMAS: &[(&str, &str)] = &[
    ("en", "English"),
    ("es", "Español"),
    ("zh", "中文"),
    ("ru", "Русский"),
    ("pt", "Português"),
];

pub fn set_lang(n: u8) {
    LANG.store(if (n as usize) < IDIOMAS.len() { n } else { 0 }, Ordering::Relaxed);
}
pub fn lang() -> u8 {
    LANG.load(Ordering::Relaxed)
}
/// Código corto del idioma activo ("en", "es"…).
pub fn codigo() -> &'static str {
    IDIOMAS.get(lang() as usize).map(|x| x.0).unwrap_or("en")
}
/// Fija el idioma por su código ("en", "es", "zh", "ru", "pt"). Devuelve si existe.
pub fn set_codigo(c: &str) -> bool {
    if let Some(i) = IDIOMAS.iter().position(|x| x.0.eq_ignore_ascii_case(c)) {
        set_lang(i as u8);
        true
    } else {
        false
    }
}

/// Fija el idioma: `es = true` → español, si no inglés. (Compatibilidad.)
pub fn set_es(es: bool) {
    set_lang(if es { 1 } else { 0 });
}

/// Autodetección desde el entorno (LANG/LC_ALL): es/zh/ru/pt, si no inglés.
pub fn autodetectar() {
    let v = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .unwrap_or_default()
        .to_lowercase();
    for (i, (c, _)) in IDIOMAS.iter().enumerate() {
        if v.starts_with(c) {
            set_lang(i as u8);
            return;
        }
    }
}

pub fn es() -> bool {
    lang() == 1
}

/// Devuelve `en` o `es_txt` según el idioma, o la traducción del diccionario
/// (chino/ruso/portugués), con inglés como respaldo.
pub fn tr(en: &'static str, es_txt: &'static str) -> &'static str {
    match lang() {
        1 => es_txt,
        n @ 2..=4 => dicc().get(en).map(|a| a[(n - 2) as usize]).unwrap_or(en),
        _ => en,
    }
}

/// Formateo en runtime: sustituye cada `{}` de la plantilla por el siguiente
/// argumento, en orden. Permite plantillas traducibles con tr().
pub fn tfmt(tpl: &str, args: &[String]) -> String {
    let mut out = String::with_capacity(tpl.len() + 16);
    let mut it = args.iter();
    let mut rest = tpl;
    while let Some(pos) = rest.find("{}") {
        out.push_str(&rest[..pos]);
        if let Some(a) = it.next() {
            out.push_str(a);
        }
        rest = &rest[pos + 2..];
    }
    out.push_str(rest);
    out
}

/// Diccionario de la superficie más visible: clave = literal inglés,
/// valor = [中文, Русский, Português]. Lo que no esté aquí sale en inglés.
fn dicc() -> &'static HashMap<&'static str, [&'static str; 3]> {
    static M: OnceLock<HashMap<&'static str, [&'static str; 3]>> = OnceLock::new();
    M.get_or_init(|| TRAD.iter().map(|&(k, zh, ru, pt)| (k, [zh, ru, pt])).collect())
}

// (inglés, 中文, Русский, Português)
#[rustfmt::skip]
const TRAD: &[(&str, &str, &str, &str)] = &[
    ("Home", "主页", "Главная", "Início"),
    ("Analysis", "分析", "Анализ", "Análise"),
    ("Explorer", "浏览器", "Обзор", "Explorador"),
    ("Compare", "比较", "Сравнить", "Comparar"),
    ("Formats", "格式", "Форматы", "Formatos"),
    ("Tools", "工具", "Инструменты", "Ferramentas"),
    ("Settings", "设置", "Настройки", "Ajustes"),
    ("Universal file exploration\nand reverse engineering", "通用文件探索\n与逆向工程", "Универсальный разбор файлов\nи обратная разработка", "Exploração universal de arquivos\ne engenharia reversa"),
    ("CORE edition", "核心版", "Редакция CORE", "Edição CORE"),
    ("PRO edition", "专业版", "Редакция PRO", "Edição PRO"),
    ("STUDIO edition", "工作室版", "Редакция STUDIO", "Edição STUDIO"),
    ("› Activate license", "› 激活许可证", "› Активировать лицензию", "› Ativar licença"),
    ("▶ Analyze", "▶ 分析", "▶ Анализ", "▶ Analisar"),
    ("■ Abort", "■ 中止", "■ Прервать", "■ Abortar"),
    ("Open output", "打开输出", "Открыть результат", "Abrir saída"),
    ("▶ Extract", "▶ 提取", "▶ Извлечь", "▶ Extrair"),
    ("Preview", "预览", "Просмотр", "Pré-visualizar"),
    ("Ask an AI", "询问 AI", "Спросить ИИ", "Perguntar a uma IA"),
    ("Search all", "全局搜索", "Искать во всём", "Buscar em tudo"),
    ("Search", "搜索", "Искать", "Buscar"),
    ("Strings", "字符串", "Строки", "Cadeias"),
    ("Switch language", "切换语言", "Сменить язык", "Mudar idioma"),
    ("Choose files", "选择文件", "Выбрать файлы", "Escolher arquivos"),
    ("Choose folder", "选择文件夹", "Выбрать папку", "Escolher pasta"),
    ("+ Files", "+ 文件", "+ Файлы", "+ Arquivos"),
    ("+ Folder", "+ 文件夹", "+ Папка", "+ Pasta"),
    ("Clear", "清除", "Очистить", "Limpar"),
    ("Output", "输出", "Вывод", "Saída"),
    ("Rescan", "重新扫描", "Пересканировать", "Reescanear"),
    ("Update available", "有可用更新", "Доступно обновление", "Atualização disponível"),
    ("Later", "稍后", "Позже", "Mais tarde"),
    ("BLOCK DETAILS", "块详情", "ДЕТАЛИ БЛОКА", "DETALHES DO BLOCO"),
    ("LAYER TREE", "层级树", "ДЕРЕВО СЛОЁВ", "ÁRVORE DE CAMADAS"),
    ("PROCESSING CORES", "处理核心", "ЯДРА ПРОЦЕССОРА", "NÚCLEOS DE PROCESSAMENTO"),
    ("MEMORY", "内存", "ПАМЯТЬ", "MEMÓRIA"),
    ("ANALYSIS ENGINES", "分析引擎", "ДВИЖКИ АНАЛИЗА", "MOTORES DE ANÁLISE"),
    ("PARAMETERS", "参数", "ПАРАМЕТРЫ", "PARÂMETROS"),
    ("KEYS (protected ZIP/RAR/7z)", "密钥（受保护的 ZIP/RAR/7z）", "КЛЮЧИ (защищённые ZIP/RAR/7z)", "CHAVES (ZIP/RAR/7z protegidos)"),
    ("Local analysis · Offline", "本地分析 · 离线", "Локальный анализ · Офлайн", "Análise local · Offline"),
    ("Supported formats", "支持的格式", "Поддерживаемые форматы", "Formatos suportados"),
];

#[cfg(test)]
mod pruebas_idioma {
    use super::*;

    #[test]
    fn traduce_o_cae_a_ingles() {
        set_codigo("zh");
        assert_eq!(tr("Analysis", "Análisis"), "分析");
        assert_eq!(tr("this string is not translated", "x"), "this string is not translated"); // fallback
        set_codigo("ru");
        assert_eq!(tr("Settings", "Ajustes"), "Настройки");
        set_es(true);
        assert_eq!(tr("Settings", "Ajustes"), "Ajustes");
        set_lang(0);
        assert_eq!(tr("Settings", "Ajustes"), "Settings");
    }
}
