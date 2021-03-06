/* global describe, it, beforeEach, expect, jasmine, spyOn */
/* eslint camelcase: 0, no-invalid-this: 0 */

const _ = require('underscore');

const Player = require('../../../server/game/player.js');

describe('Player', function () {

    function createCardSpy(num, owner) {
        var spy = jasmine.createSpyObj('card', ['moveTo', 'removeDuplicate']);
        spy.num = num;
        spy.location = 'loc';
        spy.dupes = _([]);
        spy.owner = owner;
        return spy;
    }

    beforeEach(function() {
        this.gameSpy = jasmine.createSpyObj('game', ['raiseEvent', 'raiseMergedEvent', 'queueSimpleStep', 'addMessage']);

        this.player = new Player('1', 'Test 1', true, this.gameSpy);
        spyOn(this.player, 'moveCard');

        this.callbackSpy = jasmine.createSpy('callback');

        this.card1 = createCardSpy(1, this.player);
        this.card2 = createCardSpy(2, this.player);
    });

    describe('discardCards()', function () {
        describe('when no cards are passed', function() {
            beforeEach(function() {
                this.player.discardCards([], false, this.callbackSpy);
            });

            it('should not raise the event', function() {
                expect(this.gameSpy.raiseMergedEvent).not.toHaveBeenCalled();
            });
        });

        describe('when cards are passed', function() {
            beforeEach(function() {
                this.eventOuterParams = { player: this.player, cards: [this.card1, this.card2], allowSave: false, originalLocation: 'loc' };
                this.player.discardCards([this.card1, this.card2], false, this.callbackSpy);
            });

            it('should raise the onCardsDiscarded event', function() {
                expect(this.gameSpy.raiseMergedEvent).toHaveBeenCalledWith('onCardsDiscarded', this.eventOuterParams, jasmine.any(Function));
            });

            describe('the onCardsDiscarded handler', function() {
                beforeEach(function() {
                    this.gameSpy.queueSimpleStep.and.callFake(callback => {
                        this.simpleStepCallback = callback;
                    });
                    this.eventInnerParams1 = { player: this.player, card: this.card1, allowSave: false, originalLocation: 'loc' };
                    this.eventInnerParams2 = { player: this.player, card: this.card2, allowSave: false, originalLocation: 'loc' };
                    this.onCardsDiscardedHandler = this.gameSpy.raiseMergedEvent.calls.mostRecent().args[2];
                    this.onCardsDiscardedHandler(this.eventOuterParams);
                });

                it('should raise the onCardDiscarded event for each card', function() {
                    expect(this.gameSpy.raiseMergedEvent).toHaveBeenCalledWith('onCardDiscarded', this.eventInnerParams1, jasmine.any(Function));
                    expect(this.gameSpy.raiseMergedEvent).toHaveBeenCalledWith('onCardDiscarded', this.eventInnerParams2, jasmine.any(Function));
                });

                it('should queue a step to call the callback', function() {
                    expect(this.gameSpy.queueSimpleStep).toHaveBeenCalled();
                });

                describe('the simple step callback', function () {
                    it('should call the original callback', function() {
                        this.simpleStepCallback();
                        expect(this.callbackSpy).toHaveBeenCalledWith([this.card1,this.card2]);
                    });
                });

                describe('the onCardDiscarded handler', function() {
                    beforeEach(function() {
                        this.onCardDiscardedHandler = this.gameSpy.raiseMergedEvent.calls.mostRecent().args[2];
                        this.onCardDiscardedHandler(this.eventInnerParams1);
                    });

                    it('should move the card to discard', function() {
                        expect(this.player.moveCard).toHaveBeenCalledWith(this.card1, 'discard pile');
                    });
                });
            });
        });
    });

    describe('discardCard()', function () {
        describe('when the card has dupes', function() {
            beforeEach(function() {
                this.dupe = createCardSpy(3, this.player);
                this.card1.removeDuplicate.and.returnValue(this.dupe);
                this.card1.dupes.push(this.dupe);
            });

            describe('and the discard can be saved', function() {
                beforeEach(function() {
                    this.player.discardCard(this.card1, true);
                });

                it('should not raise the onCardsDiscarded event', function() {
                    expect(this.gameSpy.raiseMergedEvent).not.toHaveBeenCalledWith('onCardsDiscarded', jasmine.any(Object), jasmine.any(Function));
                });

                it('should remove the dupe', function() {
                    expect(this.card1.removeDuplicate).toHaveBeenCalled();
                });
            });

            describe('and the discard cannot be saved', function() {
                beforeEach(function() {
                    this.eventOuterParams = { player: this.player, cards: [this.card1], allowSave: false, originalLocation: 'loc' };
                    this.player.discardCard(this.card1, false);
                });

                it('should raise the onCardsDiscarded event', function() {
                    expect(this.gameSpy.raiseMergedEvent).toHaveBeenCalledWith('onCardsDiscarded', this.eventOuterParams, jasmine.any(Function));
                });
            });
        });

        describe('when the card has no dupes', function() {
            beforeEach(function() {
                this.eventOuterParams = { player: this.player, cards: [this.card1], allowSave: false, originalLocation: 'loc' };
                this.player.discardCard(this.card1, false);
            });

            it('should raise the onCardsDiscarded event', function() {
                expect(this.gameSpy.raiseMergedEvent).toHaveBeenCalledWith('onCardsDiscarded', this.eventOuterParams, jasmine.any(Function));
            });

            describe('the onCardsDiscarded handler', function() {
                beforeEach(function() {
                    this.gameSpy.queueSimpleStep.and.callFake(callback => {
                        this.simpleStepCallback = callback;
                    });
                    this.eventInnerParams1 = { player: this.player, card: this.card1, allowSave: false, originalLocation: 'loc' };
                    this.onCardsDiscardedHandler = this.gameSpy.raiseMergedEvent.calls.mostRecent().args[2];
                    this.onCardsDiscardedHandler(this.eventOuterParams);
                });

                it('should raise the onCardDiscarded event for each card', function() {
                    expect(this.gameSpy.raiseMergedEvent).toHaveBeenCalledWith('onCardDiscarded', this.eventInnerParams1, jasmine.any(Function));
                });

                describe('the onCardDiscarded handler', function() {
                    beforeEach(function() {
                        this.onCardDiscardedHandler = this.gameSpy.raiseMergedEvent.calls.mostRecent().args[2];
                        this.onCardDiscardedHandler(this.eventInnerParams1);
                    });

                    it('should move the card to discard', function() {
                        expect(this.player.moveCard).toHaveBeenCalledWith(this.card1, 'discard pile');
                    });
                });
            });
        });
    });
});
