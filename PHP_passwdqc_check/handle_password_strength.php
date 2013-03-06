<?
  $debug = 0;
  include_once("PasswordStrengthTest.inc");

  if($debug >= 5) {
    var_dump($_REQUEST);
  }

  $params = array(
    "min" => array("disabled", 24, 11, 8, 7),
    "max" => 40,
    "passphrase" => 3,
    "match" => 4,
    "similar" => "deny",
    "random" => 47,
    "enforce" => "everyone",
    "retry" => 3,
  );

  if(!isset($_REQUEST["password"]) || $_REQUEST["password"] == "") {
    return "NO";
    exit();
  }

  if(!isset($_REQUEST["orig"]) || $_REQUEST["orig"] == "") {
    $orig = "";
  } else {
    $orig = $_REQUEST["orig"];
  }

  $pw = array();

  if(isset($_REQUEST["username"]) && $_REQUEST["username"] != "") {
    $pw["pw_name"] = $_REQUEST["username"];
  }

  setLocale(LC_CTYPE, en_US.UTF-8);
  $xx = new PasswordStrengthTest(array("debug" => $debug));
  $errors = $xx->passwdqc_check($params, $_REQUEST["password"], $orig, $pw);

  if($errors) {
    print "NO";
  } else {
    print "YES";
  }
?>
