(function($){
    $(document).ready(function(){
        var csrftoken = $("[name=csrfmiddlewaretoken]").val();
        function csrfSafeMethod(method) {
            // these HTTP methods do not require CSRF protection
            return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
        }

        $.ajaxSetup({
            beforeSend: function(xhr, settings) {
                if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
                    xhr.setRequestHeader("X-CSRFToken", csrftoken);
                }
            }
        });

        $('.account-action').on('click', function(){
            var url = $(this).data('url');
            var action = $(this).data('action');
            var title = $(this).text();
            var user = $(this).closest('tr').find('.field-username').text();
            var act = title + ' verification for user:  ' + user;
            if (action === 'decline') {
                var reason = prompt('You are going to '+ act + ' Are you sure?');
                var data = {'confirm': 'true', 'action': action, 'reason': reason};
                $.post(url, data,
                    function(resp){
                        alert('Done');
                        window.location.href = window.location.href;
                    });
            } else {
                if(confirm('You are going to '+ act + ' Are you sure?')){
                    var data = {'confirm': 'true', 'action': action};
                    $.post(url, data,
                        function(resp){
                            alert('Done');
                            window.location.href = window.location.href;
                        });
                }
            }


            return false;
        })

    });
})(django.jQuery)
