$(document).ready(function () {
    $('.deleteButton').click(function (e) {
        console.log('clicked deleteButton')
        e.preventDefault();
//        $('.modal').addClass('show');
        var value = $(this).val();
        console.log("value",value)
        $("#object_id_placeholder_div").html(`<input hidden="true" id="object_id_placeholder_input" value="` + value + `">`)
    });
    $('.CloseModal').click(function (e) {
        e.preventDefault();
//        $('.modal').removeClass('show');
    });

    $("#modal_delete_button").click(function () {
        var object_id = $("#object_id_placeholder_input").val();
        console.log('Id ',object_id)
        var protocol = window.location.protocol
        var hostname = window.location.hostname
        var port = window.location.port
        var url = protocol + "//" + hostname + ":" + port + "/adminpanel" + "/user-delete" + "/" + object_id + "/"
        window.location.href = url
    });
});
