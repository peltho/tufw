# Terminal UI for ufw
This go package provides a terminal user interface for `ufw`.

![Screenshot](preview.gif)

It allows you to add, edit or remove rules in a fancy way which is ideal when you're not familiar with `ufw` command.

> Be sure to run it as root otherwise it won't work.

## Installation
```
go install github.com/peltho/tufw@latest
```

## Dependencies
This package is based on [rivo/tview](https://github.com/rivo/tview) (and its dependencies).

## Troubleshooting
Add your issue here on Github if you spot an unwanted behavior.
Feel free to get in touch if you have any questions.

## Licence
[MIT](https://github.com/peltho/tufw/blob/main/LICENSE.txt)