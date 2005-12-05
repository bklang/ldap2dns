<?
header("Content-Type: image/gif");
passthru("/usr/bin/X11/xearth -size 500,500 -nostars -gif");
?>
