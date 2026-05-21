<?php

    echo("GET:\n");
    print_r($_GET);

    echo("POST:\n");
    print_r($_POST);

    echo("FILES:\n");
    print_r($_FILES);

    // if $_FILES is not empty, then we have a file upload
    if(isset($_FILES) && count($_FILES) > 0) {
        foreach($_FILES as $file) {
            $file_content = file_get_contents($file["tmp_name"]);
            echo("-------- FILE CONTENT: ".$file["name"]." --------\n");
            echo(
                str_replace(
                    "\n", 
                    "!n",
                    str_replace("\r", "!r", $file_content)
                )
            );
            echo("\n");
        }
    }
?>