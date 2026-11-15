use quick_xml::se::to_string;
use serde::Serialize;

pub fn to_xml<T: Serialize>(value: &T) -> Result<String, String> {
    let inner = to_string(value).map_err(|e| e.to_string())?;
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>{}",
        inner
    ))
}
