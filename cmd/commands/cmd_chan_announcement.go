package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/urfave/cli"
)

var sendChanAnnCommand = cli.Command{
	Name:     "sendchanann",
	Category: "Peers",
	Usage:    "Send a channel announcement to a peer",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "peer",
		},
		cli.Uint64Flag{
			Name: "chan_id",
			Usage: "The 8-byte compact channel ID to announce. " +
				"If this is set the chan_point param is " +
				"ignored.",
		},
		cli.StringFlag{
			Name: "chan_point",
			Usage: "The channel point in format txid:index. If " +
				"the chan_id param is set this param is " +
				"ignored.",
		},
	},
	Action: actionDecorator(sendChanAnn),
}

func sendChanAnn(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	if !ctx.IsSet("peer") {
		return fmt.Errorf("peer is required")
	}
	if !ctx.IsSet("chan_id") && !ctx.IsSet("chan_point") {
		return fmt.Errorf("specify either chan_id or chan_point")
	}

	peer, err := hex.DecodeString(ctx.String("peer"))
	if err != nil {
		return err
	}

	req := &lnrpc.SendChannelAnnouncementRequest{
		Peer: peer,
	}
	if ctx.IsSet("chan_id") {
		req.ChanId = ctx.Uint64("chan_id")
	}
	if ctx.IsSet("chan_point") {
		req.ChanPoint = ctx.String("chan_point")
	}

	resp, err := client.SendChannelAnnouncement(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}
