# qtmetaparser

an ida script to parse the qt 5 metadata, including the class, method.

## Usage
Move the cursor to the start of qt metaobject (usually in the .data segment), run the script.

qt metaobject looks like:

![](https://raw.githubusercontent.com/xzefeng/qtmetaparser/master/img/qtmetaobject.png)


after running the script:
![](https://raw.githubusercontent.com/xzefeng/qtmetaparser/master/img/qtmetaobject_parsed.png)
![](https://raw.githubusercontent.com/xzefeng/qtmetaparser/master/img/qtmetaobjectprivate_parsed.png)
## TODO
Everything except stringdata, method :)