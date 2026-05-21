<?php 
	//header("Set-Cookie: SESSION=deadbeef1234567890");
    print_r($_GET);
    print_r($_POST);

    // write file to /tmp with the json encoded string of the $_GET and $_POST and $_SERVER
    $data = array(
        'GET' => $_GET,
        'POST' => $_POST,
        'SERVER' => $_SERVER
    );

    // write to /tmp
    $file = '/tmp/karna-test'.time().'.json';
    file_put_contents($file, json_encode($data));


?>
