using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis;

namespace ProjetoA.Classes
{
    class ComplexidadeCiclomatica
    {
        public static int CalcularComplexidadeCiclomatica(string codigoCSharp)
        {
            SyntaxTree syntaxTree = CSharpSyntaxTree.ParseText(codigoCSharp);
            var complexityWalker = new ComplexityWalker();
            complexityWalker.Visit(syntaxTree.GetRoot());
            return complexityWalker.Complexity;
        }

        private class ComplexityWalker : CSharpSyntaxWalker
        {
            public int Complexity { get; private set; }

            public ComplexityWalker() : base(SyntaxWalkerDepth.Trivia)
            {
            }

            // Métodos de visita para estruturas de controle
            public override void VisitIfStatement(IfStatementSyntax node)
            {
                Complexity++;
                base.VisitIfStatement(node);
            }

            public override void VisitSwitchStatement(SwitchStatementSyntax node)
            {
                Complexity++;
                base.VisitSwitchStatement(node);
            }

            public override void VisitConditionalExpression(ConditionalExpressionSyntax node)
            {
                Complexity += 2;
                base.VisitConditionalExpression(node);
            }

            // Adicione outros métodos de visita conforme necessário para contar outras estruturas de controle
            public override void VisitForStatement(ForStatementSyntax node)
            {
                Complexity++;
                base.VisitForStatement(node);
            }
        }
    }
}