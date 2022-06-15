using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using Benaloh.RSA.Classes;

namespace Benaloh
{
    public sealed class Benaloh : ICrypto
    {
        private sealed class BenalohKeysGenerator : IKeysGenerator
        {
            private readonly PrimalityTestMode _mode;
            private readonly double _minProbability;
            private readonly ulong _length;

            public BenalohKeysGenerator(PrimalityTestMode mode, double minProbability, ulong length)
            {
                _mode = mode;
                _minProbability = minProbability;
                _length = length;
            }

            [SuppressMessage("ReSharper.DPA", "DPA0001: Memory allocation issues")]
            public Keys GenerateKeys(BigInteger message)
            {
                var keys = new Keys();
                var p = GenerateRandomPrimeNumber();
                var q = GenerateRandomPrimeNumber();
                keys.n = BigInteger.Multiply(p, q);
                keys.phi = BigInteger.Multiply(p - 1, q - 1);
                keys.r = message;
                
                while (true)
                {
                    ++keys.r;
                    if ((p - 1) % keys.r == 0
                        && BigInteger.GreatestCommonDivisor(keys.r, (p - 1) / keys.r) == 1
                        && BigInteger.GreatestCommonDivisor(keys.r, q - 1) == 1)
                        break;
                }
                
                while (true)
                {
                    var pow = BigInteger.Divide(keys.phi, keys.r);
                    keys.y = BenalohUtils.GenerateRandomInteger(1, keys.n);
                    keys.x = BigInteger.ModPow(keys.y, pow, keys.n);
                    if (keys.x != 1)
                        break;
                }
                
                return keys;
            }
            
            private BigInteger GenerateRandomPrimeNumber()
            {
                var random = new Random();
                var buffer = new byte[_length];
                while (true)
                {
                    random.NextBytes(buffer);
                    var primeNumber = new BigInteger(buffer);
                    if (primeNumber < 2)
                        continue;

                    switch (_mode)
                    {
                        case PrimalityTestMode.Fermat:
                        {
                            var test = new FermatPrimalityTest();
                            if (test.SimplicityTest(primeNumber, _minProbability))
                                return primeNumber;
                            break;
                        }
                        case PrimalityTestMode.SolovayStrassen:
                        {
                            var test = new SolovayStrassenPrimalityTest();
                            if (test.SimplicityTest(primeNumber, _minProbability))
                                return primeNumber;
                            break;
                        }
                        case PrimalityTestMode.MillerRabin:
                        {
                            var test = new MillerRabinPrimalityTest();
                            if (test.SimplicityTest(primeNumber, _minProbability))
                                return primeNumber;
                            break;
                        }
                        default:
                            throw new ArgumentOutOfRangeException();
                    }
                }
            }
        }

        private readonly BenalohKeysGenerator _keygen;
        private Keys _keys;
        
        public Benaloh(BigInteger message, PrimalityTestMode mode, double minProbability, ulong length)
        {
            _keygen = new BenalohKeysGenerator(mode, minProbability, length);
            _keys = _keygen.GenerateKeys(message);
        }

        public BigInteger Encrypt(BigInteger message)
        {
            // BigInteger u = BenalohUtils.GenerateRandomInteger(2, _keys.n - 1);
            BigInteger u;
            while (true)
            {
                u = BenalohUtils.GenerateRandomInteger(2, _keys.n - 1);
                if (BigInteger.GreatestCommonDivisor(u, _keys.n) == 1)
                    break;
            }
            var left = BigInteger.ModPow(_keys.y, message, _keys.n);
            var right = BigInteger.ModPow(u, _keys.r, _keys.n);
            return BigInteger.Multiply(left, right) % _keys.n;
        }

        public BigInteger Decrypt(BigInteger message)
        {
            BigInteger md = 0;
            var a = BigInteger.ModPow(message, _keys.phi / _keys.r, _keys.n);
            for (BigInteger i = 0;  i < _keys.r; i++)
            {
                var result = BigInteger.ModPow(_keys.x, i, _keys.n);
                if (result == a)
                    md = i;
            }
            return md;
        }

        public void GenerateKeys(BigInteger message)
        {
            _keys = _keygen.GenerateKeys(message);
        }
    }
}