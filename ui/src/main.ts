import { mount } from "svelte";
import "./app.css";
import App from "./App.svelte";
import { store } from "./lib/store.svelte";

// Block the browser context menu and reload shortcuts: this is an app, not a web page.
window.addEventListener("contextmenu", (e) => {
  if (!(e.target instanceof HTMLInputElement)) e.preventDefault();
});
window.addEventListener("keydown", (e) => {
  if (e.key === "F5" || (e.ctrlKey && (e.key === "r" || e.key === "R" || e.key === "p" || e.key === "P"))) e.preventDefault();
});

store.init();
export default mount(App, { target: document.getElementById("app")! });
