package main

import "embed"

const asciiArtBanner = `
       _
  __ _| |__   ___  _ __   ___ _   _
 / _` + "`" + ` | '_ \ / _ \| '_ \ / _ \ | | |
| (_| | | | | (_) | | | |  __/ |_| |
 \__, |_| |_|\___/|_| |_|\___|\__, |
 |___/                        |___/

`

// Embed static assets in the binary
//
//go:embed static/*
var staticAssets embed.FS
