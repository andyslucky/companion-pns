use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sqlx::types::time::OffsetDateTime;
use time::macros::format_description;
pub fn deserialize_offset_datetime<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    let str_value = String::deserialize(deserializer)?;

    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second] [offset_hour sign:mandatory]:[offset_minute]");

    Ok(OffsetDateTime::parse(str_value.as_ref(), &format).map_err(serde::de::Error::custom)?)
}

pub fn serialize_offset_datetime<'de, S>(odt: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second] [offset_hour sign:mandatory]:[offset_minute]");
    let str_format: String = odt.format(&format).map_err(serde::ser::Error::custom)?;
    str_format.serialize(serializer)
}
