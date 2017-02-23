const DrawCard = require('../../../drawcard.js');

class DoransGame extends DrawCard {
    setupCardAbilities() {
        this.reaction({
            when: {
                afterChallenge: (event, challenge) => (
                    challenge.winner === this.controller &&
                    challenge.strengthDifference >= 5 &&
                    challenge.challengeType === 'intrigue' 
                )
            },
            handler: () => {
                var power = this.controller.plotDiscard.size();

                this.game.addPower(this.controller, power);
                this.game.addMessage('{0} uses {1} to gain {2} power for their faction', this.controller, this, power);
            }
        });
    }
}

DoransGame.code = '01119';

module.exports = DoransGame;
