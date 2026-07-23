(() => {
  const button = document.querySelector("[data-select-all-devices]");
  const checkboxes = [...document.querySelectorAll('input[name="device_id"]')];
  if (!button || checkboxes.length === 0) {
    return;
  }

  const updateButton = () => {
    const allSelected = checkboxes.every((checkbox) => checkbox.checked);
    button.textContent = allSelected ? "Clear selection" : "Select all";
    button.setAttribute("aria-pressed", String(allSelected));
  };

  button.addEventListener("click", () => {
    const selectAll = !checkboxes.every((checkbox) => checkbox.checked);
    checkboxes.forEach((checkbox) => {
      checkbox.checked = selectAll;
    });
    updateButton();
  });
  checkboxes.forEach((checkbox) => checkbox.addEventListener("change", updateButton));
  updateButton();
})();
