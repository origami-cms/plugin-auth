# Origami Single Page App plugin

This is a very simply Origami plugin that serves a HTML file as a fallback for routes not found.

## Installation
`yarn add origami-plugin-spa`

## Configuration
In your `.origami` file, add this to your `plugins`:


```JSON
{
    ...
    "plugins": {
        "spa": {
            "fallback": "./dist/index.html"
        }
    }
    ...
}
```


## Options:
### `fallback`
String path value pointing to the location of the HTML file to fallback to (relative to project).
