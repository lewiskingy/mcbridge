function renderDoc(slug) {
  const container = document.getElementById("doc");
  if (!container) return;

  const targetSlug = slug || container.dataset.docSlug || "readme";
  if (!targetSlug) {
    container.classList.remove("loading");
    container.textContent = "No documentation available.";
    return;
  }
  container.classList.add("loading");
  container.textContent = "Loading documentation…";

  fetch(`/docs/content/${encodeURIComponent(targetSlug)}`)
    .then(response => {
      if (!response.ok) {
        throw new Error(`Failed to load ${targetSlug}`);
      }
      return response.text();
    })
    .then(markdown => {
      container.innerHTML = marked.parse(markdown);
      container.classList.remove("loading");
    })
    .catch(err => {
      container.classList.remove("loading");
      container.textContent = err.toString();
    });
}

document.addEventListener("DOMContentLoaded", () => renderDoc());
