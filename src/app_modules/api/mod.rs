pub mod v1;

use actix_web::web;

use v1::routes::user_routes;

pub fn api_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api/v1").configure(user_routes));
}
