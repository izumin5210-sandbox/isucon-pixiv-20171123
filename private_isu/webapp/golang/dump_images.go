package main

import (
	"fmt"
	"net/http"
	"sync"
)

func dumpImages(w http.ResponseWriter, r *http.Request) {
	limit := 100
	i := 0
	for {
		posts := []*Post{}
		err := db.Select(&posts, fmt.Sprintf("SELECT `id`, `mime`, `imgdata` FROM `posts` LIMIT %d OFFSET %d", limit, i*limit))
		if err != nil {
			panic(err)
		}
		if len(posts) == 0 {
			w.WriteHeader(http.StatusOK)
			break
		}

		var wg sync.WaitGroup

		for _, post := range posts {
			wg.Add(1)
			go func(p *Post) {
				defer wg.Done()
				ext := ""
				switch p.Mime {
				case "image/jpeg":
					ext = "jpg"
				case "image/png":
					ext = "png"
				case "image/gif":
					ext = "gif"
				default:
					panic("Unknown image format")
				}
				err := writeImage(p.ID, ext, p.Imgdata)
				if err != nil {
					panic(err)
				}
			}(post)
		}
		wg.Wait()
		i++
	}
}
