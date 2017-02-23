const _ = require('underscore');

const DrawCard = require('../../../drawcard.js');

class ConsolidationOfPower extends DrawCard {
    setupCardAbilities() {
        this.action({
            method: 'selectCharacters',
            phase: 'marshal'
        });
    }

    selectCharacters(player) {
        this.selectedStrength = 0;

        this.game.promptForSelect(player, {
            numCards: 99,
            activePromptTitle: 'Select characters',
            waitingPromptTitle: 'Waiting for opponent to use ' + this.name,
            cardCondition: card => {
                return !card.kneeled && (card.getStrength() + this.selectedStrength <= 4 || card.opponentSelected || card.selected);
            },
            onCardToggle: (player, card) => {
                if(card.opponentSelected || card.selected) {
                    this.selectedStrength += card.getStrength();
                } else {
                    this.selectedStrength -= card.getStrength();
                }
            },
            onSelect: (player, cards) => this.onSelect(player, cards),
            onCancel: (player) => this.cancelSelection(player)
        });
    }

    onSelect(player, cards) {
        this.cards = cards;

        this.game.promptForSelect(player, {
            activePromptTitle: 'Select character to gain power',
            waitingPromptTitle: 'Waiting for opponent to use ' + this.name,
            cardCondition: card => {
                return _.contains(this.cards, card);
            },
            onSelect: (player, card) => this.onPowerSelected(player, card),
            onCancel: (player) => this.cancelSelection(player)
        });

        return true;
    }

    onPowerSelected(player, card) {
        _.each(this.cards, card => {
            card.controller.kneelCard(card);
        });

        card.modifyPower(1);

        this.game.addMessage('{0} uses {1} to kneel {2}', player, this, this.cards);
        this.game.addMessage('{0} uses {1} to have {2} gain 1 power', player, this, card);

        this.selectedStrength = 0;

        return true;
    }

    cancelSelection(player) {
        this.selectedStrength = 0;

        this.game.addMessage('{0} cancels the resolution of {1}', player, this);
    }
}

ConsolidationOfPower.code = '01062';

module.exports = ConsolidationOfPower;
