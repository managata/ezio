//
//
//

package main

func main() {
	parseFlags()
	eOpen()
	defer eClose()

	switch true {
	case oP.Archive:
		CreateArchive()
	case oP.Extract:
		ExtractArchive()
	case oP.List:
		ListArchive(true)
	case oP.View:
		ListArchive(false)
	case oP.Test:
		TestArchive()
	}

	eStatus()

	return
}
