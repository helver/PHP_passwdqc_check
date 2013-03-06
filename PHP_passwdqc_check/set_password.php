<?
  session_start();
  $_SESSION["username"] = 'bob';
  session_write_close();
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML+RDFa 1.0//EN" "http://www.w3.org/MarkUp/DTD/xhtml-rdfa-1.dtd">
<html>
<head>
  <style type="text/css">
.alert {
  padding: 8px 35px 8px 14px;
  margin-bottom: 18px;
  text-shadow: 0 1px 0 rgba(255, 255, 255, 0.5);
  background-color: #fcf8e3;
  border: 1px solid #fbeed5;
  -webkit-border-radius: 4px;
  -moz-border-radius: 4px;
  border-radius: 4px;
  color: #c09853;
}
.alert-heading {
  color: inherit;
}
.alert .close {
  position: relative;
  top: -2px;
  right: -21px;
  line-height: 18px;
}
.alert-success {
  background-color: #dff0d8;
  border-color: #d6e9c6;
  color: #468847;
}
.alert-danger,
.alert-error {
  background-color: #f2dede;
  border-color: #eed3d7;
  color: #b94a48;
}
.alert-info {
  background-color: #d9edf7;
  border-color: #bce8f1;
  color: #3a87ad;
}
.alert-block {
  padding-top: 14px;
  padding-bottom: 14px;
}
.alert-block > p,
.alert-block > ul {
  margin-bottom: 0;
}
.alert-block p + p {
  margin-top: 5px;
}
.close {
  float: right;
  font-size: 20px;
  font-weight: bold;
  line-height: 18px;
  color: #000000;
  text-shadow: 0 1px 0 #ffffff;
  opacity: 0.2;
  filter: alpha(opacity=20);
}
.close:hover {
  color: #000000;
  text-decoration: none;
  cursor: pointer;
  opacity: 0.4;
  filter: alpha(opacity=40);
}
  </style>
  <script src="//ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js"></script>
  <script type="text/javascript">
<!-- // --><![CDATA[//><!--
  function capitalizeFirstLetter(string)
  {
    return string.charAt(0).toUpperCase() + string.substring(1);
  }

  function generate_confirm_div(args)
  {
    var default_args = {
                'sf'      : "success",
                'message' : "",
                'label'   : "",
    };
    for(var index in default_args) {
      if(typeof args[index] === "undefined") { args[index] = default_args[index]; }
    }

    return "<div class=\"messages alert alert-" +
           args["sf"] +
           "\"><a class=\"close\" data-dismiss=\"alert\" href=\"#\">x</a>" +
           (args["label"] == "" ? "" : "<h4 class=\"alert-heading\">" + capitalizeFirstLetter(args["label"]) + "</h4>") +
           args["message"] +
           "</div>";
  }

  $(window).load(function(){

    $('#pass1').change(function() {
      $('#valid_pass2').html("");
      var vars = {'password': $('#pass1').val(), 'username': $('#username').val()};
      var checker = $.post('handle_password_strength.php',vars).done(function(data) {
        if(data == "NO"){
          $('#valid_pass1').html(generate_confirm_div({'sf':'fail', 'message':'Low password strength.'}));
        } else {
          $('#valid_pass1').html(generate_confirm_div({'sf': 'success', 'message':'Acceptable password strength.'}));
        }
      });
    });

    $('#pass2').change(function() {
      if($('#pass1').val() !== $('#pass2').val()) {
        $('#valid_pass2').html(generate_confirm_div({'sf':'fail', 'message':'Passwords do not match.'}));
      } else {
        $('#valid_pass2').html(generate_confirm_div({'sf':'success', 'message':'Passwords match.'}));
      }
    });
  });
// --><!]]>
  </script>
</head>
<body>
  <h1 class="title page-header" id="page-title">Set Password</h1>
  <form enctype="multipart/form-data" action="doSetPassword.php" method="POST" accept-charset="UTF-8">
    <input type="hidden" name="username" value="<?= $_SESSION["username"] ?>" />
    <div>Password: <input type="password" id="pass1" name="pass1" size="25" maxlength="128" /><p id="valid_pass1"></p></div>
    <div>Confirm Password: <input type="password" id="pass2" name="pass2" size="25" maxlength="128" /><p id="valid_pass2"></p></div>
    <input class="btn btn-primary btn-large form-submit" type="submit" id="edit-submit" name="op" value="Save" />
  </form>
</body>
</html>
