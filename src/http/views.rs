pub const STYLES: &str = r#"
:root {
  --white: #ffffff;
  --black: #000000;
  --gray: #555555;
  --light-gray: #f0f0f0;
  --yellow: #f0c000;
  --background: var(--white);
  --background-secondary: var(--black);
  --text: var(--black);
  --text-secondary: var(--white);
  --link: var(--black);
  --link-hover: var(--gray);
}

html,
body {
  box-sizing: border-box;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
  font-size: 100%;
  font-synthesis: none;
  text-rendering: optimizeLegibility;
  background: var(--background);
  margin: 0;
  padding: 0;
  color: var(--text);
}

*,
*:before,
*:after {
  box-sizing: inherit;
  padding: 0;
  margin: 0;
  overflow-wrap: break-word;
}

body {
  padding: 0;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  overflow-x: hidden;
  max-width: 100vw;
}

header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 1rem;
  background-color: var(--background-secondary);
  color: var(--text-secondary);
  padding: 1rem;
  font-size: 0.8rem;
}

header a {
  color: var(--text-secondary);
  text-decoration: none;
  padding: 0.15rem 0.5rem;
  margin: 0.15rem 0;
  display: inline-block;
}

header a.active {
  color: var(--text);
  background: var(--background);
}

.main-content {
  padding: 3rem;
  width: 100%;
  margin: 0 auto;
  flex: 1;
}

h1,
h2,
h3,
h4 {
  margin: 1rem 0;
  border-bottom: solid 1px var(--text);
}

h1 {
  font-size: 3rem;
  letter-spacing: -5px;
}

h2 {
  font-size: 2.5rem;
  letter-spacing: -2px;
}

h3 {
  font-size: 1.5rem;
  letter-spacing: -1px;
  border-bottom: none;
}

p {
  font-size: 1rem;
  margin: 0.7rem 0;
}

a {
  color: var(--link);
  cursor: pointer;
}

input, textarea, select {
  width: 100%;
  padding: 0.5rem;
  background: var(--light-gray);
  color: var(--text);
  border: 1px solid var(--text);
  font-family: inherit;
  margin-bottom: 1rem;
}

button {
  padding: 0.5rem 1rem;
  background: var(--text);
  color: var(--background);
  border: none;
  font-family: inherit;
  cursor: pointer;
  font-weight: bold;
}

button:hover {
  opacity: 0.8;
}

pre {
  white-space: pre-wrap;
  word-wrap: break-word;
}

table {
  border-collapse: collapse;
  width: 100%;
  margin: 1rem 0;
  table-layout: fixed;
}

th,
td {
  border: 1px solid var(--text);
  padding: 0.5rem;
  text-align: left;
}

th {
  background-color: var(--text);
  color: var(--background);
}

img {
  max-width: 100%;
  height: auto;
}

/* D3 Graph Styles */
.links line { stroke: var(--text); stroke-opacity: 0.6; }
.nodes circle { stroke: var(--background); stroke-width: 1px; fill: var(--text); r: 5; }
text { font-family: inherit; font-size: 10px; fill: var(--text); }

.graph-container {
  border: 1px solid var(--text);
  margin: 1rem 0;
  background: var(--light-gray);
}
"#;

pub fn base_layout(title: &str, content: &str) -> String {
    format!(
        r#"
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{}</title>
        <style>{}</style>
      </head>
      <body>
        {}
      </body>
    </html>
    "#,
        title, STYLES, content
    )
}

pub fn layout(title: &str, content: &str) -> String {
    base_layout(title, content)
}
