"use strict";
/* global AdminI18n, DataTable, _post:readable, BASE_URL:readable, reload:readable, jdenticon:readable */

function deleteOrganization(event) {
    event.preventDefault();
    event.stopPropagation();
    const org_uuid = event.currentTarget.dataset.vwOrgUuid;
    const org_name = event.currentTarget.dataset.vwOrgName;
    const billing_email = event.currentTarget.dataset.vwBillingEmail;
    if (!org_uuid) {
        alert(AdminI18n.message("Required parameters not found!"));
        return false;
    }

    // First make sure the user wants to delete this organization
    const continueDelete = confirm(AdminI18n.t("WARNING: All data of this organization ({org_name}) will be lost!\nMake sure you have a backup, this cannot be undone!", { org_name }));
    if (continueDelete == true) {
        const input_org_uuid = prompt(AdminI18n.t("To delete the organization \"{org_name} ({billing_email})\", please type the organization uuid below.", { org_name, billing_email }));
        if (input_org_uuid != null) {
            if (input_org_uuid == org_uuid) {
                _post(`${BASE_URL}/admin/organizations/${org_uuid}/delete`,
                    "Organization deleted correctly",
                    "Error deleting organization"
                );
            } else {
                alert(AdminI18n.message("Wrong organization uuid, please try again"));
            }
        }
    }
}

function initActions() {
    document.querySelectorAll("button[vw-delete-organization]").forEach(btn => {
        btn.addEventListener("click", deleteOrganization);
    });

    if (jdenticon) {
        jdenticon();
    }
}

// onLoad events
document.addEventListener("DOMContentLoaded", (/*event*/) => {
    const columnCount = document.getElementById("orgs-table").querySelectorAll("thead th").length;
    new DataTable("#orgs-table", {
        "drawCallback": function () {
            initActions();
        },
        "stateSave": true,
        "language": AdminI18n.tableLanguage(),
        "responsive": true,
        "lengthMenu": [
            [-1, 5, 10, 25, 50],
            [AdminI18n.t("All"), 5, 10, 25, 50]
        ],
        "pageLength": -1, // Default show all
        "columnDefs": [{
            "targets": [columnCount - 2, columnCount - 1], // Do not include the last two columns into the search/order features
            "searchable": false,
            "orderable": false
        }]
    });

    // Add click events for organization actions
    initActions();

    const btnReload = document.getElementById("reload");
    if (btnReload) {
        btnReload.addEventListener("click", reload);
    }
});
