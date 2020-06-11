package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
)

const PEER_ERROR_NOT_FOUND = 0
const PEER_OK = 1
const PEER_OTHER_ERROR = 2
const PEER_ERROR_UNKNOWN = 3

type result struct {
	Channel     string `xml:"channel"`
	Value       string `xml:"value"`
	Valuelookup string `xml:"ValueLookup"`
}

type prtgbody struct {
	XMLName xml.Name `xml:"prtg"`
	Res     []result `xml:"result"`
}

type amiparams struct {
	AsteriskIP   string
	AsteriskPort string
	AMIUser      string
	AMIPassword  string
}

type StationData struct {
	CheckPeerExt    string
	Response        string
	ResponseInt     int
	ErrorMessage    string
	StatioStatusInt int
	StstionStatus   string
	StationCallerID string
	StationExt      string
	CannelType      string
}

func RespToMap(stresp string) map[string]string {
	var rmap map[string]string
	rmap = make(map[string]string, 0)
	ass := strings.Split(stresp, "\r\n")
	for _, assentry := range ass {
		assformap := strings.Split(assentry, ":")
		if len(assformap) == 2 {

			rmap[assformap[0]] = strings.TrimSpace(assformap[1])
		}
	}
	return rmap
}

func main() {
	username := flag.String("u", "prtg", "asterisk AMI username")
	passwd := flag.String("p", "prtg", "aterisk AMI password")
	aaip := flag.String("i", "", "aterisk IP address")
	aaport := flag.String("dp", "5038", "asterisk MII port, default 5038")
	Peers := flag.String("peers", "", "peers for monitoring, single number or multiple comma separated list like: 101,102,703,805")
	flag.Parse()

	var StstionDataAll []StationData
	sm := amiparams{*aaip, *aaport, *username, *passwd}
	conn, err := net.Dial("tcp", sm.AsteriskIP+":"+sm.AsteriskPort)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	scanner := bufio.NewScanner(conn)

	AuthStr := fmt.Sprintf("Action: login\r\nUsername: %s\r\nSecret: %s\r\nEvents: off\r\nActionID: 23456063340\r\n\r\n", sm.AMIUser, sm.AMIPassword)

	LogooffStr := "Action: logoff\r\n\r\n"

	for scanner.Scan() {
		conn.Write([]byte(AuthStr))
		break
	}

	scanner2 := bufio.NewScanner(conn)
	scanner2.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {

		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}

		if i := strings.Index(string(data), "\r\n\r\n"); i >= 0 {
			return i + len("\r\n\r\n"), data[0 : i+len("\r\n\r\n")], nil
		}

		if atEOF {
			return len(data), data, nil
		}

		return
	})

	scanner2.Scan()
	AuthRespT := scanner2.Text()

	authrespm := RespToMap(AuthRespT)

	if authrespm["Message"] == "Authentication accepted" {
		PeersSl := strings.Split(*Peers, ",")
		SipPeerStr := ""
		for _, Peer := range PeersSl {
			FormatPeer := strings.TrimSpace(Peer)
			SipPeerStr = fmt.Sprintf("Action: SIPshowpeer\r\nActionID: 23456063340\r\nPeer: %s\r\n\r\n", FormatPeer)
			conn.Write([]byte(SipPeerStr))
			scanner2.Scan()
			respt := scanner2.Text()
			sipregm := RespToMap(respt)

			if val, ok := sipregm["ActionID"]; ok {
				if val == "23456063340" {

					var StationDataSingle StationData
					StationDataSingle.CheckPeerExt = Peer

					if val, ok := sipregm["Response"]; ok {
						Responsestring := strings.TrimSpace(val)
						StationDataSingle.Response = Responsestring
						if Responsestring == "Error" {
							ErrorMessage := "Response Error"
							if val, ok := sipregm["Message"]; ok {
								ErrorMessage = val
							}
							StationDataSingle.ErrorMessage = ErrorMessage
						}
					}

					if val, ok := sipregm["Callerid"]; ok {
						Cscallid := strings.TrimSpace(val)
						Cscallid = strings.ReplaceAll(Cscallid, "<", "")
						Cscallid = strings.ReplaceAll(Cscallid, ">", "")
						Cscallid = strings.ReplaceAll(Cscallid, "\"", "")
						StationDataSingle.StationCallerID = Cscallid
					}
					if val, ok := sipregm["Status"]; ok {
						Cscallid := strings.TrimSpace(val)
						CscallidSl := strings.Split(Cscallid, " ")
						Cscallid = CscallidSl[0]
						StationDataSingle.StstionStatus = Cscallid
					}
					if val, ok := sipregm["ObjectName"]; ok {
						Cscallid := strings.TrimSpace(val)
						CscallidSl := strings.Split(Cscallid, " ")
						Cscallid = CscallidSl[0]
						StationDataSingle.StationExt = Cscallid
					}
					if val, ok := sipregm["Channeltype"]; ok {
						Cscallid := strings.TrimSpace(val)
						CscallidSl := strings.Split(Cscallid, " ")
						Cscallid = CscallidSl[0]
						StationDataSingle.CannelType = Cscallid
					}

					StstionDataAll = append(StstionDataAll, StationDataSingle)
				}
			}
		}
	}

	conn.Write([]byte(LogooffStr))
	scanner2.Scan()
	conn.Close()

	var rd1 []result

	for StationIndex, rres := range StstionDataAll {
		StstionDataAll[StationIndex].StatioStatusInt = PEER_OTHER_ERROR
		if rres.Response != "Success" {
			if rres.ErrorMessage != "" {
				PeerNotFoundStrn := fmt.Sprintf("Peer %s not found.", rres.CheckPeerExt)
				if rres.ErrorMessage == PeerNotFoundStrn {
					StstionDataAll[StationIndex].StatioStatusInt = PEER_ERROR_NOT_FOUND
				}
			}
		} else {
			if rres.StstionStatus == "OK" {
				StstionDataAll[StationIndex].StatioStatusInt = PEER_OK
			} else {
				if rres.StstionStatus == "UNKNOWN" {
					StstionDataAll[StationIndex].StatioStatusInt = PEER_ERROR_UNKNOWN
				}
			}
		}
		ChannelName := fmt.Sprintf("Ext: %s CallerID: %s", rres.CheckPeerExt, rres.StationCallerID)
		ChannelValue := fmt.Sprintf("%d", StstionDataAll[StationIndex].StatioStatusInt)

		rd1 = append(rd1, result{ChannelName, ChannelValue, "AsteriskStation"})
	}

	mt1 := &prtgbody{Res: rd1}
	bolB, _ := xml.Marshal(mt1)
	fmt.Println(string(bolB))
}
