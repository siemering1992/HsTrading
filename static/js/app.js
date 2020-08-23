// Show toasts

$(function (){
    // Show side
    $('body').removeClass('hidden');

    // Init and show all toats
    let toast = $('.toast');
    toast.toast({"delay": 20000});
    toast.toast("show");

});

