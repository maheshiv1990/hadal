use actix_web::{HttpResponse, delete, get, post, web};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppError;

#[derive(Serialize, sqlx::FromRow)]
pub struct Note {
    id: Uuid,
    title: String,
    body: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewNote {
    title: String,
    #[serde(default)]
    body: String,
}

impl NewNote {
    fn validate(&self) -> Result<(), AppError> {
        let title_len = self.title.trim().chars().count();
        if title_len == 0 || title_len > 200 {
            return Err(AppError::BadRequest(
                "title must be 1-200 characters".into(),
            ));
        }
        if self.body.chars().count() > 10_000 {
            return Err(AppError::BadRequest(
                "body must be at most 10000 characters".into(),
            ));
        }
        Ok(())
    }
}

#[get("/notes")]
pub async fn list(pool: web::Data<PgPool>) -> Result<HttpResponse, AppError> {
    let notes = sqlx::query_as::<_, Note>(
        "SELECT id, title, body, created_at FROM notes ORDER BY created_at DESC LIMIT 100",
    )
    .fetch_all(pool.get_ref())
    .await?;
    Ok(HttpResponse::Ok().json(notes))
}

#[post("/notes")]
pub async fn create(
    pool: web::Data<PgPool>,
    payload: web::Json<NewNote>,
) -> Result<HttpResponse, AppError> {
    payload.validate()?;
    let note = sqlx::query_as::<_, Note>(
        "INSERT INTO notes (id, title, body) VALUES ($1, $2, $3)
         RETURNING id, title, body, created_at",
    )
    .bind(Uuid::new_v4())
    .bind(payload.title.trim())
    .bind(&payload.body)
    .fetch_one(pool.get_ref())
    .await?;
    Ok(HttpResponse::Created().json(note))
}

#[get("/notes/{id}")]
pub async fn get(pool: web::Data<PgPool>, id: web::Path<Uuid>) -> Result<HttpResponse, AppError> {
    let note =
        sqlx::query_as::<_, Note>("SELECT id, title, body, created_at FROM notes WHERE id = $1")
            .bind(id.into_inner())
            .fetch_one(pool.get_ref())
            .await?;
    Ok(HttpResponse::Ok().json(note))
}

#[delete("/notes/{id}")]
pub async fn delete(
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let result = sqlx::query("DELETE FROM notes WHERE id = $1")
        .bind(id.into_inner())
        .execute(pool.get_ref())
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(HttpResponse::NoContent().finish())
}
