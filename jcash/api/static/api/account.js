var FILESTACK_APIKEY = 'AnARH4cA6SiuvN5hCQvdCz';

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

        var fs_client = filestack.init(FILESTACK_APIKEY);

        $('#id_document_type').hide();
        var btn = $('<a href="javascript:void(0)">Upload new passport</a>');
        $('#id_document_url').parent().append(btn);
        btn.on('click', function(){

            fs_client.pick({
                onFileUploadFinished: function(file){
                    $('#id_document_url').val(file.url);
                    var parts = file.filename.split('.');
                    var ext = parts[parts.length - 1]
                    $('#id_document_type').val(ext);
                }
            })
        
        });

        $('input[name=_save]').after('<input type="submit" value="Save and re-verify" class="default" name="_reverify">');

        $('.account-action').on('click', function(){
            var url = $(this).data('url');
            var action = $(this).data('action');
            var title = $(this).text();
            var user = $(this).closest('tr').find('.field-username').text();
            var act = title + ' verification for user:  ' + user;
            if(confirm('You are going to '+ act + ' Are you sure?')){
                // console.log('');
                var data = {'confirm': 'true', 'action': action};
                $.post(url, data,
                    function(resp){
                        alert('Done');
                        window.location.href = window.location.href;
                    });
            }
            return false;
        })

    });
})(django.jQuery)