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

#[test]
fn collapse_hides_all_but_selected_and_no_general_header() {
    assert!(!JS.contains("col && c.key !== S.cur && !c.unread"), "unread must not keep entries visible");
    assert!(JS.contains("if (col && c.key !== S.cur) continue;"));
    assert!(JS.contains("if (sec === 0) box.append(body)"), "Allgemein without header");
    assert!(JS.contains("c.key === S.cur ? 0 : c.unread"), "badge counts hidden only");
}

#[test]
fn alt_b_ignored_while_typing_and_fab_hidden_on_mobile() {
    assert!(JS.contains("INPUT|TEXTAREA|SELECT"));
    assert!(include_str!("../web/style.css").contains("@media (max-width:720px){#sbfab{display:none}}"));
}
