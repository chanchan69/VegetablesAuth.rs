# VegetablesAuth.rs
A simple Vegetables Auth wrapper for Rust

# Login
```
use vege_auth::AuthClient;

let client = AuthClient::new("your_aid", "your_api_key", "your_client_secret", None);

let response = client
    .add_credentials("chanchan", "chanchan's password")
    .authenticate();

match response {
    Ok(r) => { println!("Successfully logged in, your license type is: {:?}", r.license_type) }
    Err(e) => { println!("An error occurred: {:?}", e.error_type) }
}
```

# Register

```
use vege_auth::AuthClient;

let client = AuthClient::new("your_aid", "your_api_key", "your_client_secret", None);

let response = client
    .add_credentials("chanchan", "chanchan's password")
    .add_contact("chanchan@sirchanchan.dev")
    .add_key("LICENSE-dfg-dfhjgdkjfg-eruteuirt")
    .register();

println!("Auth message: {}", response);
```

# Reset HWID

```
use vege_auth::AuthClient;

let client = AuthClient::new("your_aid", "your_api_key", "your_client_secret", None);

let response = client
    .add_credentials("chanchan", "chanchan's password")
    .add_key("RESET-dfg-dfhjgdkjfg-eruteuirt")
    .reset();

println!("Auth message: {}", response);
```
