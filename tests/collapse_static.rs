// JS-free checks of the static collapse/sidebar-toggle parts.
const HTML: &str = include_str!("../web/index.html");
const JS: &str = include_str!("../web/app.js");

#[test]
fn toggle_controls_present_and_accessible() {
    for id in ["id=\"colall\"", "id=\"sbfab\"", "id=\"memsec\"", "id=\"menu\""] { assert!(HTML.contains(id), "{id}"); }
    assert!(HTML.contains("aria-controls=\"side\""));
    assert!(!HTML.contains("<details"), "members section is a button header now");
}

#[test]
fn section_headers_use_button_aria_and_safe_text() {
    for s in ["'aria-expanded'", "'aria-controls'", "type: 'button', class: 'shead'", "molt.collapsed", "molt.sidebar"] { assert!(JS.contains(s), "{s}"); }
    assert!(!JS.contains("innerHTML"), "only textContent/createTextNode");
}
