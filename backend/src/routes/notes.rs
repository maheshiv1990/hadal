use actix_web::{HttpResponse, delete, get, post, web};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::AuthUser;
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

// Every query below is scoped to the signed-in user's `owner_id`
// (lint:notes-owner-scope, CASA 3.1.4). Another user's note is reported as
// 404, exactly like a missing one, so IDs can't be probed.

#[get("")]
pub async fn list(user: AuthUser, pool: web::Data<PgPool>) -> Result<HttpResponse, AppError> {
    let notes = sqlx::query_as::<_, Note>(
        "SELECT id, title, body, created_at FROM notes
         WHERE owner_id = $1 ORDER BY created_at DESC LIMIT 100",
    )
    .bind(user.user_id)
    .fetch_all(pool.get_ref())
    .await?;
    Ok(HttpResponse::Ok().json(notes))
}

#[post("")]
pub async fn create(
    user: AuthUser,
    pool: web::Data<PgPool>,
    payload: web::Json<NewNote>,
) -> Result<HttpResponse, AppError> {
    payload.validate()?;
    let note = sqlx::query_as::<_, Note>(
        "INSERT INTO notes (id, owner_id, title, body) VALUES ($1, $2, $3, $4)
         RETURNING id, title, body, created_at",
    )
    .bind(Uuid::new_v4())
    .bind(user.user_id)
    .bind(payload.title.trim())
    .bind(&payload.body)
    .fetch_one(pool.get_ref())
    .await?;
    Ok(HttpResponse::Created().json(note))
}

#[get("/{id}")]
pub async fn get(
    user: AuthUser,
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let note = sqlx::query_as::<_, Note>(
        "SELECT id, title, body, created_at FROM notes WHERE id = $1 AND owner_id = $2",
    )
    .bind(id.into_inner())
    .bind(user.user_id)
    .fetch_one(pool.get_ref())
    .await?;
    Ok(HttpResponse::Ok().json(note))
}

#[delete("/{id}")]
pub async fn delete(
    user: AuthUser,
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let result = sqlx::query("DELETE FROM notes WHERE id = $1 AND owner_id = $2")
        .bind(id.into_inner())
        .bind(user.user_id)
        .execute(pool.get_ref())
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(HttpResponse::NoContent().finish())
}
