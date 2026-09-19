(function () {
  "use strict";

  function normalizePath(path) {
    if (!path) {
      return "/";
    }

    path = path.split("?")[0].split("#")[0];

    if (!path.startsWith("/")) {
      path = "/" + path;
    }

    if (path.length > 1 && !path.endsWith("/")) {
      path += "/";
    }

    return path;
  }

  function updateActiveNavigation() {
    const nav = document.getElementById("psv-global-nav");

    if (!nav) {
      return;
    }

    const currentPath = normalizePath(window.location.pathname);

    const links = nav.querySelectorAll(
      ".psv-global-nav__link"
    );

    links.forEach(function (link) {
      const linkUrl = new URL(link.href, window.location.origin);
      const linkPath = normalizePath(linkUrl.pathname);

      let isActive = false;

      if (linkPath === "/") {
        isActive = currentPath === "/";
      } else {
        isActive =
          currentPath === linkPath ||
          currentPath.startsWith(linkPath);
      }

      link.classList.toggle(
        "psv-global-nav__link--active",
        isActive
      );

      if (isActive) {
        link.setAttribute("aria-current", "page");
      } else {
        link.removeAttribute("aria-current");
      }
    });
  }

  /*
   * Initial page load.
   */
  document.addEventListener(
    "DOMContentLoaded",
    updateActiveNavigation
  );

  /*
   * Material for MkDocs instant navigation.
   *
   * document$ emits whenever a new page is loaded through
   * navigation.instant, without a full browser refresh.
   */
  if (typeof document$ !== "undefined") {
    document$.subscribe(function () {
      updateActiveNavigation();
    });
  }
})();
