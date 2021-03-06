/*global describe, it, beforeEach, expect, jasmine*/
/*eslint camelcase: 0, no-invalid-this: 0 */

const BaseCard = require('../../../server/game/basecard.js');

describe('BaseCard', function () {
    beforeEach(function () {
        this.testCard = { code: '111', label: 'test 1(some pack)', name: 'test 1' };
        this.limitedCard = { code: '1234', text: 'Limited.' };
        this.nonLimitedCard = { code: '2222', text: 'Stealth.' };
        this.card = new BaseCard({}, this.testCard);
    });

    describe('when new instance created', function() {
        it('should generate a new uuid', function() {
            expect(this.card.uuid).not.toBeUndefined();
        });
    });

    describe('doAction()', function() {
        describe('when there is no action for the card', function() {
            beforeEach(function() {
                this.card.abilities.actions = [];
            });

            it('does not crash', function() {
                expect(() => this.card.doAction('player', 0)).not.toThrow();
            });
        });

        describe('when there are actions for the card', function() {
            beforeEach(function() {
                this.actionSpy1 = jasmine.createSpyObj('action', ['execute']);
                this.actionSpy2 = jasmine.createSpyObj('action', ['execute']);
                this.card.abilities.actions = [this.actionSpy1, this.actionSpy2];
            });

            it('should call execute on the action with the appropriate index', function() {
                this.card.doAction('player', 1);
                expect(this.actionSpy2.execute).toHaveBeenCalledWith('player', 1);
            });

            it('should handle out of bounds indices', function() {
                this.card.doAction('player', 3);
                expect(this.actionSpy1.execute).not.toHaveBeenCalled();
                expect(this.actionSpy2.execute).not.toHaveBeenCalled();
            });
        });
    });

    describe('getSummary', function() {
        describe('when is active player', function() {
            beforeEach(function () {
                this.summary = this.card.getSummary(true);
            });

            describe('and card is faceup', function() {
                it('should return card data', function() {
                    expect(this.summary.uuid).toEqual(this.card.uuid);
                    expect(this.summary.name).toEqual(this.testCard.label);
                    expect(this.summary.code).toEqual(this.testCard.code);
                });

                it('should not return facedown', function() {
                    expect(this.summary.facedown).toBeFalsy();
                });
            });

            describe('and card is facedown', function() {
                beforeEach(function () {
                    this.card.facedown = true;
                    this.summary = this.card.getSummary(true);
                });

                it('should return card data', function() {
                    expect(this.summary.uuid).toEqual(this.card.uuid);
                    expect(this.summary.name).toEqual(this.testCard.label);
                    expect(this.summary.code).toEqual(this.testCard.code);
                });

                it('should return facedown', function() {
                    expect(this.summary.facedown).toBe(true);
                });
            });
        });

        describe('when is not active player', function() {
            beforeEach(function () {
                this.summary = this.card.getSummary(false);
            });

            describe('and card is faceup', function() {
                describe('and hiding facedown cards', function() {
                    beforeEach(function() {
                        this.summary = this.card.getSummary(false, true);
                    });

                    it('should return no card data', function () {
                        expect(this.summary.uuid).toBeUndefined();
                        expect(this.summary.name).toBeUndefined();
                        expect(this.summary.code).toBeUndefined();
                    });

                    it('should return facedown', function() {
                        expect(this.summary.facedown).toBe(true);
                    });
                });

                it('should return card data', function () {
                    expect(this.summary.uuid).toEqual(this.card.uuid);
                    expect(this.summary.name).toEqual(this.testCard.label);
                    expect(this.summary.code).toEqual(this.testCard.code);
                });

                it('should not return facedown', function() {
                    expect(this.summary.facedown).toBe(false);
                });
            });

            describe('and card is facedown', function() {
                beforeEach(function () {
                    this.card.facedown = true;
                    this.summary = this.card.getSummary(false);
                });

                it('should return no card data', function() {
                    expect(this.summary.uuid).toBeUndefined();
                    expect(this.summary.name).toBeUndefined();
                    expect(this.summary.code).toBeUndefined();
                });

                it('should return facedown', function() {
                    expect(this.summary.facedown).toBe(true);
                });
            });
        });
    });
});
