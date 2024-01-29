<?php
if (isset($_GET['url'])) {
    $url = $_GET['url'];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    $result = curl_exec($ch);
    curl_close($ch);
    echo $result;
    die();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Free CURL Service</title>
</head>
<body>
    <form action="">
        <input type="text" name="url" placeholder="Enter URL">
        <input type="submit" value="Submit">
    </form>
</body>
</html>