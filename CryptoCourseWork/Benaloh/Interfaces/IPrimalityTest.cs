using System.Numerics;

namespace Benaloh
{
    internal interface IPrimalityTest
    {
        public bool SimplicityTest(BigInteger n, double minProbability);
    }
}