const DrawCard = require('../../../drawcard.js');

class Confinement extends DrawCard {
    setupCardAbilities() {
        this.action({
            method: 'selectCharacter'
        });
    }

    selectCharacter(player) {
        this.game.promptForSelect(player, {
            cardCondition: card => card.location === 'play area' && card.getType() === 'character' && card.getStrength() <= 4,
            activePromptTitle: 'Select a character',
            waitingPromptTitle: 'Waiting for opponent to use ' + this.name,
            onSelect: (player, card) => this.onCardSelected(player, card)
        });
    }

    onCardSelected(player, card) {
        this.untilEndOfPhase(ability => ({
            match: card,
            effect: [
                ability.effects.removeIcon('military'),
                ability.effects.removeIcon('intrigue'),
                ability.effects.removeIcon('power')
            ]
        }));

        return true;
    }
}

Confinement.code = '01121';

module.exports = Confinement;
