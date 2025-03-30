use actix_web::web;

use super::auth_endpoints;
use super::user_endpoints;

// Grouped routes for users
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .service(user_endpoints::get_user)
            .service(user_endpoints::register),
    )
    .service(web::scope("/auth").service(auth_endpoints::login));
}
